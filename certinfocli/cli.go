package main

import (
	"fmt"
	"github.com/greensnark/certinfo"
	"os"
)

func booleanNot(res bool) string {
	if res {
		return ""
	} else {
		return "NOT "
	}
}

func main() {
	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [certificate/key file] ...\n", os.Args[0])
		os.Exit(1)
	}

	objects := []certinfo.Object{}
	for _, file := range os.Args[1:] {
		obj, err := certinfo.ParseFile(file)
		objects = append(objects, obj)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Could not parse %s: %s\n", file, err)
			continue
		}
		fmt.Printf("%s: %s\n", file, obj)
	}

	eachPermutation(objects, func(cert, key certinfo.Object) {
		if certinfo.IsCertificate(cert) && certinfo.IsKey(key) {
			privateKeyMatch, err := cert.(certinfo.Certificates).PrivateKeyMatches(key.(certinfo.Key))
			if err != nil {
				fmt.Printf("%s is private key for %s: unknown: %v\n", err)
			} else {
				fmt.Printf("%s is %sthe private key for %s\n", key.SourceFile(), booleanNot(privateKeyMatch),
					cert.SourceFile())
			}
		}
	})
}

func eachPermutation(objects []certinfo.Object, permuter func(a, b certinfo.Object)) {
	for _, left := range objects {
		for _, right := range objects {
			if left != right {
				permuter(left, right)
			}
		}
	}
}
