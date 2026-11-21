# redactor

A tool that removes sensitive data (passwords, tokens, API keys, card numbers,
emails) from NDJSON logs of API traffic. It runs as a command-line tool or as an
HTTP service, and the rules for what to redact live in a YAML file.

```
redactor [--rules rules.yaml] [input-file]                # command line
redactor --serve [--addr :8080] [--rules rules.yaml]      # HTTP service
```

## Contents

1. [Build, run and test](#1-build-run-and-test)
2. [Design decisions and trade-offs](#2-design-decisions-and-trade-offs)
3. [The JWT report](#3-the-jwt-report)
4. [Deployment files](#4-deployment-files)
5. [Known limitations and what I'd do with more time](#5-known-limitations-and-what-id-do-with-more-time)
6. [Inline on live traffic with a sub-millisecond budget](#6-inline-on-live-traffic-with-a-sub-millisecond-budget)

## 1. Build, run and test

Requires Go 1.27 or later. The only dependency is the YAML parser
(`go.yaml.in/yaml/v3`, the maintained successor of `gopkg.in/yaml.v3`).

```sh
go build -o redactor .        # on Windows: go build -o redactor.exe .
go test ./...
go vet ./...
```

### Command line

```sh
./redactor testdata/input.ndjson > redacted.ndjson   # read a file
./redactor < testdata/input.ndjson                   # or standard input
./redactor --rules my-rules.yaml input.ndjson        # other rules (flags go before the file)
```

Redacted lines go to stdout. Problems and the summary go to stderr. For the
sample file:

```
redactor: line 20 rejected: truncated JSON
redactor: line 21 rejected: unexpected data after JSON value
redactor: line 50 rejected: truncated JSON
redactor: 48 lines, 3 rejected, 2 blank lines skipped
redactor: redactions per rule:
  auth-headers         9
  api-key-names        8
  secret-fields        10
  card-number-fields   5
  cvv-fields           1
  secret-assignment    1
  email                31
  jwt                  4
  credit-card          17
  api-key-prefix       2
```

Exit codes: `0` success, `1` the rules or the input couldn't be read (or
writing failed), `2` wrong command line. stdout and stderr are separate
streams; in a terminal they can appear interleaved.

### Service

```sh
./redactor --serve --addr :8080 --rules rules.yaml

curl -X POST --data-binary @testdata/input.ndjson http://localhost:8080/redact
curl http://localhost:8080/healthz
```

| Endpoint | |
|---|---|
| `POST /redact` | The request body is NDJSON; the response (`application/x-ndjson`) is the redacted NDJSON, streamed back while the request is still being read. |
| `GET /healthz` | `200 {"status":"ok","rules":10}`: the service is running and its rules are loaded. Used for both the Kubernetes readiness and liveness probes (see [section 2](#the-service)). |

Other methods on these paths get `405 Method Not Allowed`. The service logs
one summary line per request, plus the line number and reason of every
rejected line, to stderr. On Ctrl+C or SIGTERM it stops accepting connections
and waits up to 20 seconds for running requests to finish.

### Docker and Kubernetes

```sh
docker build -t redactor:1.0 .
docker run -p 8080:8080 redactor:1.0                                    # service
docker run -i --rm redactor:1.0 --rules /etc/redactor/rules.yaml < testdata/input.ndjson   # CLI

# in a local cluster with kind (https://kind.sigs.k8s.io)
kind create cluster
kind load docker-image redactor:1.0
kubectl apply -f deploy/kubernetes/
kubectl port-forward service/redactor 8080:80
```

### Project layout

```
main.go                  command line: flags, CLI mode, service mode
internal/redact/         the redaction engine
  rules.go               loading and validating rules.yaml
  redactor.go            the four actions, and value rules on one string
  walk.go                walking one JSON line; key rules
  text.go                strings with their own structure: JSON, form data, query strings
  stream.go              reading and writing line by line; error records
  luhn.go                the Luhn check
internal/server/         the HTTP service
deploy/kubernetes/       ConfigMap, Deployment, Service
Dockerfile
testdata/input.ndjson    the provided sample
```

There are tests next to each part, plus end-to-end tests in `main_test.go`
that run the whole sample file: every planted secret must be gone from the
output (apart from the personal data noted in section 5), broken lines must
not be printed anywhere, and running the tool on its own output must change
nothing.

## 2. Design decisions and trade-offs

### Reading the JSON: a token stream, not a map

The simple approach is `json.Unmarshal` into a `map[string]any`. I didn't use
it because it changes the data in ways a log redactor shouldn't:

- Go maps have no order, so every line would come out with its keys sorted,
  which makes it hard to compare input and output.
- Duplicate keys (sample line 25) collapse into one.
- Numbers become floats: `12345678901234567890` turns into
  `12345678901234567000`, and `10.50` into `10.5`.

Instead, each line is read as a stream of tokens (`json.Decoder.Token` with
`UseNumber`) and the output is written token by token. `walk` reads exactly
one JSON value and calls `walkObject` / `walkArray`, which call `walk` again
for every key's value or element. That recursion handles any nesting.

- Key order, duplicate keys and the exact text of numbers are kept. Spaces
  between tokens are not (output is compact JSON).
- Escapes are decoded before matching, so `alice@example.com`
  (line 45) is seen as an email.
- Go's HTML escaping is turned off, so `Tom & Jerry` isn't written as
  `Tom & Jerry`.
- Nesting deeper than 1000 levels is rejected, so a hostile line can't make
  the recursion run out of memory.

### Where rules apply

- `headers` objects get header-scoped key rules and `body` values get
  body-scoped ones. This switch only happens at the top level of a
  transaction (and inside `response`), so a field called `headers` inside a
  body is still body data.
- Anything outside a headers object, including unexpected top-level fields,
  gets body rules, so an extra field can't hide a password from the rules.
- Exact key names are compared case-insensitively, because HTTP header names
  are (`authorization`, `AUTHORIZATION`, lines 2 and 14).
- The first matching key rule wins, and it applies to everything under the
  key: every string and number inside an array or object. `Set-Cookie: [a, b]`
  becomes `["****","****"]`. `null`, `true` and `false` can't hold a secret
  and are left as they are. `remove` drops the key and its whole value.
- Value rules run on every string, in file order, each on the result of the
  previous one. They also run on numbers (a card number stored as a number)
  and on keys (an email used as a key). A number changed by a rule becomes a
  string, because `****1111` isn't a number.

### Strings with their own structure

A body that is a string often has structure inside it that the key rules
would otherwise never see. A body string is tried, in order, as:

1. **JSON** (a complete, valid object or array): redacted recursively with
   body rules, and written back as a string (lines 1, 10, 11).
2. **Form data** (`a=1&b=2`, matched strictly: no spaces, no bare `=` in a
   value): each pair is URL-decoded (`bob%40example.com`) and gets the key
   rules and value rules. Pairs that don't change are kept exactly as written
   (line 8).
3. **Plain text**: value rules only.

The query string in `path` is treated like form data, so `?token=...` gets the
same key rule as a body field called `token` (line 30).

I chose to detect the format from the content rather than trust the
`Content-Type` header: the header can be missing or wrong, and it may come
after the body in the line. The strict checks keep false matches rare. The
cost is that formats I don't parse (multipart, XML) only get the value rules.

### The actions

- `mask` replaces the value with `****`.
- `partial` keeps the last 4 characters (characters, not bytes, so Hebrew or
  emoji aren't cut in half). A value of 4 characters or fewer is masked
  completely; otherwise `"card_number":"1234"` (line 38) would be shown in full.
- `hash` writes `sha256:` followed by the hex digest. The prefix says what the
  value is, and a value that is already in this form isn't hashed again, which
  keeps the tool idempotent.
- `remove` drops a key, or deletes the matched text.
- Empty values are left alone: there's nothing to hide.

### Idempotency

Running the tool on its own output changes nothing: no rule matches what the
actions write, hashing skips values that are already hashed, `partial` turns
stars into the same stars, and error records are valid JSON that passes
through unchanged. Every engine test redacts its output a second time, and an
end-to-end test does the same for the whole sample.

### Streaming, memory and time

Input is read and written one line at a time, so a file far larger than
memory is fine.

- **Memory** grows with the longest line, not the file. A line over 16 MiB is
  read to its end without being kept, and replaced by an error record. (Go's
  usual line reader, `bufio.Scanner`, stops reading altogether on a line that's
  too long, so I wrote a small reader on top of `bufio.Reader.ReadSlice`.)
- **Time** is linear in the input size, times the number of value rules: each
  rule's regex scans each string once. Go's regex engine (RE2) always runs in
  linear time, so a crafted input can't make a pattern take exponential time.

### Failure handling

**Rules.** The rules file is checked strictly when it's loaded: unknown fields
(a typo like `pattren`), a bad regex, an unknown action, scope or validator, a
duplicate rule name, a pattern that matches empty text, or an unsupported
version. Any problem stops the program before it reads input or starts
listening. Nothing is ever written without rules.

**Lines.**

- Blank lines are dropped (and counted).
- A line that can't be redacted (truncated JSON, a plain-text log line, too
  long, nested too deeply) is replaced by an error record such as
  `{"redactor_error":"truncated JSON","line":20}`, and reported on stderr.

I chose error records because the content of a line we couldn't parse can't
be trusted to be redacted (line 20 has a token that is cut off, so the JWT
pattern wouldn't recognise it). The output stays valid NDJSON, the gap is
visible and points to the input line, and the record passes unchanged through
a second run. The alternatives each fail on one of these: passing the line
through can leak, dropping it silently hides data loss, and stopping the run
lets one bad line block everything after it.

The reasons printed come from a fixed list. Go's JSON errors can quote a
character from the input, so they are never printed as they are. Each line is
built in a buffer and written only if it was redacted completely.

### The summary

Counts are per rule, in rule-file order, and include rules with 0 redactions,
because a 0 can be the first sign of a broken rule. Only values that actually
changed are counted, so running the tool on its own output reports zero.

### The service

- `POST /redact` uses the same `Process` function as the CLI: it takes any
  reader and writer, so it works on a file and stdout, or on a request body
  and a response.
- With HTTP/1.1, Go's server stops reading the request body once it starts
  writing the response. Streaming needs both at once, so the handler turns on
  full duplex (`http.ResponseController.EnableFullDuplex`). A test checks that
  output starts arriving while the request is still being sent.
- Every request gets its own `Redactor`, because a Redactor's counts must not
  be updated by two requests at once. The rules are read-only after loading
  and shared by all requests.
- If something fails halfway (the client disconnects, say), the `200` status
  has already been sent. The handler then aborts the connection
  (`panic(http.ErrAbortHandler)`), so the client sees a broken response rather
  than a shorter one that looks complete.
- `/healthz` means "running with its rules loaded". The rules are loaded and
  checked before the server listens, and the program exits if they're broken,
  so any answer means the service can redact. A pod with broken rules never
  becomes ready, gets no traffic, and shows as `CrashLoopBackOff`. That is how
  the service never passes traffic through unredacted.
- On SIGTERM it stops accepting new connections and waits up to 20 seconds
  for running requests, which is less than Kubernetes' default 30-second grace
  period.
- `ReadHeaderTimeout` stops a client from holding a connection open by sending
  its headers very slowly. There's no limit on reading the body, because a
  large upload can legitimately take a long time.

### Changes to rules.yaml

The format is unchanged. I changed three rules and added one:

- `jwt`: fixed the character set ([section 3](#3-the-jwt-report)).
- `credit-card`: also matches the usual printed groupings, 4-4-4-4 and
  4-6-5 / 4-6-4, separated by spaces or dashes (lines 1, 6, 36, 44). I listed
  the exact groupings instead of allowing a separator anywhere, because a
  regex takes the longest match it can: in `4111 1111 1111 1111 12 items` the
  looser pattern takes 18 digits, which fail Luhn, so the real card would
  leak. The Luhn check ignores spaces and dashes.
- `secret-assignment` (new): masks `password=...`, `token=...` and similar
  names written inside free text (line 41). The whole pair is masked, because
  a value rule replaces its whole match and Go's regex engine can't match
  "only the part after `password=`". It runs first, so a pair is masked in one
  piece. Form data and query strings are split into pairs before value rules
  run, so there the key rules apply and the name is kept (`password=****`).

## 3. The JWT report

**What was wrong.** The `jwt` pattern used the standard base64 alphabet
(`A-Z a-z 0-9 + / =`). JWTs use **base64url** (RFC 7515), which replaces `+`
and `/` with `-` and `_`, and drops the `=` padding, so tokens can travel in
URLs and headers. When a token contains `-` or `_`:

- in the **signature**, the match stops at that character, so the end of the
  token leaks: line 15 came out as `"****_adQssw5c"`;
- in the **header or payload**, the part never reaches its `.`, so nothing
  matches and **the whole token leaks**: lines 11 and 16 (payload
  `eyJhIjoiPz8_In0`).

A typical HS256 signature is 43 random base64url characters. The chance that
at least one is `-` or `_` is 1 − (62/64)^43 ≈ 75%, so roughly three in four
real tokens were at least partly leaked. That matches "misses some JWTs seen
in production". Tokens in `Authorization` headers were still safe, because
that header's key rule masks the whole value; the leaks were in bodies, free
text and JSON stored inside strings.

**What I did.** Changed the character class to `[A-Za-z0-9_-]` (the `-` goes
last so it means a literal dash, not a range). The signature may still be
empty, for unsigned tokens.

**How I know it's fixed.** On the sample, the `jwt` count went from 2 to 4
(lines 11, 15 twice, and 16), and no `eyJ` is left in the output. Tests run
the three sample tokens, an unsigned token and a non-token (`Bearer
abc.def.ghi`) against the shipped `rules.yaml`, and the end-to-end test checks
that no token appears in the output.

**Still not covered:** a token whose header JSON starts with a space
(`{ "alg"` encodes to `eyAi`, not `eyJ`), and encrypted JWTs (JWE), which have
five parts: the pattern masks the first three and leaves the last two.

## 4. Deployment files

### Dockerfile

- **Multi-stage build.** The first stage uses the Go image to run the tests
  and compile; the final image gets only the compiled program. The tests run
  during the build, so an image can't be built from failing code.
- **Static binary on distroless.** `CGO_ENABLED=0` makes a program that needs
  no system libraries, so the final image is `gcr.io/distroless/static`: no
  shell and no package manager, which means less to attack and less to patch.
  `-trimpath -ldflags="-s -w"` leaves local paths and debug information out.
- **Not root.** It runs as user `65532`, given as a number so Kubernetes can
  verify `runAsNonRoot`.
- **Dependencies are downloaded in their own step** (copy `go.mod` and
  `go.sum`, then `go mod download`), so Docker's cache reuses them when only
  code changes. `.dockerignore` leaves out `.git`, editor folders and the
  README for the same reason.
- **Default rules are included** at `/etc/redactor/rules.yaml`, so the image
  works with plain `docker run`. `ENTRYPOINT` is the program and `CMD` holds
  its default arguments (service mode), so arguments given to `docker run`
  replace them, for example to use the CLI.

I don't have Docker on my machine, so I haven't built the image myself. I
checked the build command it runs (a static binary of about 6 MB) and that the
tests pass with only the files Docker receives.

### Kubernetes (`deploy/kubernetes/`)

- **ConfigMap `redactor-rules`** holds `rules.yaml` and is mounted at
  `/etc/redactor` in every pod, so the rules can change without rebuilding
  the image. It's a copy of the root `rules.yaml`; `TestConfigMapMatchesRulesFile`
  fails if the copies ever differ. The program reads its rules when it starts,
  so after changing them run `kubectl rollout restart deployment/redactor`.
- **Deployment `redactor`**:
  - two replicas;
  - rolling updates with `maxUnavailable: 0`, so a new pod is ready before an
    old one stops, which also makes a rules change a zero-downtime restart;
  - readiness and liveness probes on `/healthz`;
  - `terminationGracePeriodSeconds: 30` (graceful shutdown takes at most 20);
  - security settings: non-root, no privilege escalation, read-only root
    filesystem, all capabilities dropped, default seccomp profile;
  - a memory request of 64 MiB and limit of 256 MiB. Memory per request is
    bounded by the longest line (16 MiB), so the limit leaves room for several
    requests with very long lines at once. There's a CPU request but no CPU
    limit: a CPU limit only slows the service down when it's busy.
- **Service `redactor`** (`ClusterIP`, port 80 → container port 8080): one
  stable address inside the cluster (`http://redactor/redact`). It is not
  exposed outside the cluster.

## 5. Known limitations and what I'd do with more time

**Coverage**

- **Personal data.** Line 37 has an SSN, a phone number and a date of birth.
  They aren't on the required list, so I didn't add rules for them. Covering
  them by field name (`ssn`, `phone`, `dob`) is a one-line change in
  `rules.yaml`; finding them in free text is riskier, because those patterns
  also match ordinary numbers and dates.
- **`secret-assignment`** only catches `name=value` written without spaces:
  not `password: hunter2`, and not `user_password=x` (a `\b` boundary doesn't
  fall before `password` there). It also masks the name along with the value.
  With more time I'd add an optional `group` field to value rules, to redact
  only one capture group of the match; that would be a change to the config
  format.
- Card numbers with dots as separators, or unusual groupings, aren't matched.
- Bodies in formats I don't parse (multipart, XML) only get the value rules.

**Output**

- `hash` is a plain SHA-256, so a hashed email can be found by hashing likely
  emails and comparing. A keyed hash (HMAC with a secret from the
  environment) would prevent that while still letting equal values be
  matched.
- `partial` masks separators too (`***************1111`) and keeps the length
  visible. Keeping separators (`**** **** **** 1111`) would be friendlier.
- Whitespace inside a JSON line isn't preserved, and a number redacted by a
  rule becomes a string.

**Service**

- The response is sent in chunks of about 4 KB rather than line by line:
  faster overall, but a slow client sees results in bursts.
- `/redact` has no authentication, and there's no limit on request size or
  on concurrent requests. Inside a cluster I'd add a NetworkPolicy so only the
  log pipeline can call it.

**Optional bonuses I didn't do**

- **Hot-reload of the rules.** I'd check the file every few seconds and
  compare its contents (Kubernetes updates a mounted ConfigMap by swapping a
  symlink, which simple file watchers can miss), swap the rules with an
  `atomic.Pointer` so running requests finish with the rules they started
  with, and keep serving with the last good rules, logging loudly, if a new
  file doesn't load. In Kubernetes, `rollout restart` already gives a
  zero-downtime update.
- **Prometheus metrics.** The per-rule counters already exist per request;
  they'd be added to process-wide counters and served on `/metrics`.
- **A worker pool** that redacts lines in parallel while keeping their order.
- **Deployment extras:** a PodDisruptionBudget, a NetworkPolicy, autoscaling,
  and a pipeline that builds, tests and pushes the image.

## 6. Inline on live traffic with a sub-millisecond budget

Inline, the redactor would sit in the request path, so I'd move it from a
separate service into the proxy process itself (as a library, or a sidecar
over a Unix socket) and redact one request at a time instead of an NDJSON
stream, which removes a network hop that alone can cost more than the budget.
Inside, I'd stop allocating per token: `json.Decoder.Token` allocates for
every value, so I'd use a scanner that copies everything byte for byte and
only looks at keys and strings, and reuse buffers between requests instead of
allocating new ones. Key rules would become a hash-map lookup on the lowercased
key name, with the result cached, since the same header and field names
appear on almost every request. Instead of running every value regex over
every string, I'd first check cheaply for the fixed text each rule needs
(`@` for emails, `eyJ` for JWTs, a run of digits for cards, `sk_` for API
keys) and only run a regex when that text is present. I'd cap how many body
bytes are inspected inline and send larger bodies to an asynchronous path. To
stay fail-closed under the time limit, a request that runs over its budget
would have its body masked entirely rather than passed through. Finally, I'd
measure all of this with Go benchmarks and the profiler against realistic
traffic, and track the 99th-percentile latency rather than the average.
