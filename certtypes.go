package certinfo

import "crypto/x509"

type ObjectEncoding int

const (
	ObjectEncodingUnknown ObjectEncoding = iota
	ObjectEncodingDER
	ObjectEncodingPEM
)

type ObjectInfo struct {
	sourceFile string
	encoding   ObjectEncoding
	objectType ObjectType
	repr       interface{}
}

type CertificateInfo struct {
	*ObjectInfo
}

type KeyInfo struct {
	*ObjectInfo
}

func (o *ObjectInfo) SourceFile() string       { return o.sourceFile }
func (o *ObjectInfo) Encoding() ObjectEncoding { return o.encoding }
func (o *ObjectInfo) Type() ObjectType         { return o.objectType }
func (o *ObjectInfo) Repr() interface{}        { return o.repr }

func (c *CertificateInfo) Certificates() []*x509.Certificate {
	return c.ObjectInfo.repr.([]*x509.Certificate)
}

var _ Object = &ObjectInfo{}
var _ Certificates = &CertificateInfo{}

type ObjectType int

const (
	ObjectTypeUnknown = iota
	ObjectTypeX509Certificate
	ObjectTypeRSAKey
)

type Object interface {
	SourceFile() string
	Encoding() ObjectEncoding
	Type() ObjectType
	Repr() interface{}
}

type Certificates interface {
	Certificates() []*x509.Certificate
	PrivateKeyMatches(key Key) (bool, error)
	Object
}

type Key interface {
	Object
}

func IsCertificate(obj Object) bool {
	return obj.Type() == ObjectTypeX509Certificate
}

func IsKey(obj Object) bool {
	return obj.Type() == ObjectTypeRSAKey
}
