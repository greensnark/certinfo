package certinfo

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
)

var ErrEmptyPem = errors.New("empty pem")
var ErrUnsupportedKeyType = errors.New("unsupported private key type")

func GuessFileType(file string) ObjectType {
	switch strings.ToLower(filepath.Ext(file)) {
	case ".cer", ".crt":
		return ObjectTypeX509Certificate
	case ".key":
		return ObjectTypeRSAKey
	default:
		return ObjectTypeUnknown
	}
}

func PemBytes(bytes []byte) ([]byte, error) {
	block, _ := pem.Decode(bytes)
	if len(block.Bytes) == 0 {
		return nil, ErrEmptyPem
	}
	return block.Bytes, nil
}

func DerOctets(bytes []byte) ([]byte, ObjectEncoding, error) {
	pemBytes, err := PemBytes(bytes)
	if err == nil {
		return pemBytes, ObjectEncodingPEM, nil
	}
	return bytes, ObjectEncodingDER, nil
}

func FileDerOctets(file string) ([]byte, ObjectEncoding, error) {
	fileBytes, error := ioutil.ReadFile(file)
	if error != nil {
		return nil, ObjectEncodingUnknown, error
	}
	return DerOctets(fileBytes)
}

func ParseCertificate(file string) (Object, error) {
	octets, encoding, err := FileDerOctets(file)
	if err != nil {
		return nil, err
	}
	certs, err := x509.ParseCertificates(octets)
	if err != nil {
		return nil, err
	}

	return &CertificateInfo{&ObjectInfo{
		sourceFile: file,
		encoding:   encoding,
		objectType: ObjectTypeX509Certificate,
		repr:       certs,
	}}, nil
}

func ParseKey(file string) (Key, error) {
	octets, encoding, err := FileDerOctets(file)
	if err != nil {
		return nil, err
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(octets)
	if err != nil {
		return nil, err
	}
	return &KeyInfo{&ObjectInfo{
		sourceFile: file,
		encoding:   encoding,
		objectType: ObjectTypeRSAKey,
		repr:       rsaKey,
	}}, nil
}

func ParseFile(file string) (Object, error) {
	cert, certerr := ParseCertificate(file)
	if certerr == nil {
		return cert, nil
	}

	key, keyerr := ParseKey(file)
	if keyerr == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Could not parse %s as a certificate (%v) or private key (%v)", file, certerr, keyerr)
}

func (c *CertificateInfo) FirstCertificate() *x509.Certificate {
	return c.Certificates()[0]
}

func (c *CertificateInfo) PublicKeyBitSize() int {
	return KeyModulusBitSize(c.FirstCertificate().PublicKey.(*rsa.PublicKey).N)
}

func (c *CertificateInfo) PrivateKeyMatches(key Key) (bool, error) {
	rsakey, ok := key.Repr().(*rsa.PrivateKey)
	if !ok {
		return false, ErrUnsupportedKeyType
	}
	return RsaPublicKeysEqual(&rsakey.PublicKey, c.FirstCertificate().PublicKey.(*rsa.PublicKey)), nil
}

func (c *CertificateInfo) String() string {
	cert := c.Certificates()[0]
	subjectName := PkixNameString(&cert.Subject)
	issuerName := PkixNameString(&cert.Issuer)
	if issuerName == subjectName {
		issuerName = "self"
	}
	return fmt.Sprintf("Certificate: Subject=%s Issuer=%s Key-Size=%d", strconv.Quote(subjectName), strconv.Quote(issuerName), c.PublicKeyBitSize())
}

func (k *KeyInfo) RSAKey() *rsa.PrivateKey {
	return k.repr.(*rsa.PrivateKey)
}

func (k *KeyInfo) BitSize() int {
	return KeyModulusBitSize(k.RSAKey().D)
}

func (k *KeyInfo) String() string {
	return fmt.Sprintf("RSA Key: %d bits", k.BitSize())
}
