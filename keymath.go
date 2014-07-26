package certinfo

import (
	"crypto/rsa"
	"math/big"
)

func KeyModulusBitSize(mod *big.Int) int {
	return mod.BitLen()
}

func RsaPublicKeysEqual(a, b *rsa.PublicKey) bool {
	return a.E == b.E && a.N.Cmp(b.N) == 0
}
