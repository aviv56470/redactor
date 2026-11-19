package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("this goes to stdout")
	fmt.Fprintln(os.Stderr, "this goes to stderr")
}
