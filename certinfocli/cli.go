package main

import (
	"fmt"
	"github.com/greensnark/certinfo"
	"os"
)

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
			if err == nil && privateKeyMatch {
				fmt.Printf("%s (cert) === (private key) %s\n", cert.SourceFile(), key.SourceFile())
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
