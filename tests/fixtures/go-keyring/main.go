// Command go-keyring exercises the Secret Service through zalando/go-keyring,
// the library the GitHub and GitLab CLIs use. It prints one result per line.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"
)

func fail(step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(1)
}

func main() {
	const service, user, secret = "gh:github.com", "bob", "tok-from-go"

	if err := keyring.Set(service, user, secret); err != nil {
		fail("set", err)
	}
	got, err := keyring.Get(service, user)
	if err != nil {
		fail("get", err)
	}
	if got != secret {
		fail("get", fmt.Errorf("got %q, want %q", got, secret))
	}
	fmt.Println("roundtrip ok")

	if err := keyring.Set(service, user, "tok-2"); err != nil {
		fail("overwrite", err)
	}
	if got, _ = keyring.Get(service, user); got != "tok-2" {
		fail("overwrite", fmt.Errorf("got %q, want tok-2", got))
	}
	fmt.Println("overwrite ok")

	if err := keyring.Delete(service, user); err != nil {
		fail("delete", err)
	}
	if _, err := keyring.Get(service, user); !errors.Is(err, keyring.ErrNotFound) {
		fail("get after delete", fmt.Errorf("expected ErrNotFound, got %v", err))
	}
	fmt.Println("delete ok")
}
