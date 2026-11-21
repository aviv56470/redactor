# ---- Stage 1: build ----
# The official Go image has the compiler and tools. It is only used to build:
# none of it ends up in the final image.
FROM golang:1.27 AS build
WORKDIR /src

# Copy the dependency list first and download dependencies in a step of its
# own. Docker caches every step, so this one only runs again when go.mod or
# go.sum change, not on every code change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Run the tests as part of the build, so an image can't be built from code
# that fails them.
RUN go test ./...

# CGO_ENABLED=0 makes a static binary that needs no system libraries, so it
# can run in an image that contains almost nothing else.
# -trimpath leaves local folder paths out of the binary, and -ldflags="-s -w"
# leaves out debugging information, which makes it smaller.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/redactor .

# ---- Stage 2: run ----
# distroless/static holds only what a static binary needs. There is no shell
# and no package manager: less for an attacker to use and less to keep
# patched. The "nonroot" variant is set up to run as an unprivileged user.
FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/redactor /redactor

# Default rules, so the image works on its own (docker run). In Kubernetes,
# the ConfigMap is mounted over /etc/redactor and replaces this file.
COPY rules.yaml /etc/redactor/rules.yaml

# Run as user 65532 ("nonroot"), never as root. A number rather than a name,
# so Kubernetes can check runAsNonRoot.
USER 65532:65532

EXPOSE 8080

# The program, and its default arguments. Anything given after the image
# name in "docker run" replaces the default arguments (CMD), for example to
# use the CLI instead of the service.
ENTRYPOINT ["/redactor"]
CMD ["--serve", "--addr", ":8080", "--rules", "/etc/redactor/rules.yaml"]
