package certinfo

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

var OidMap = map[string]string{
	"2.5.4.6":  "C",
	"2.5.4.8":  "ST",
	"2.5.4.7":  "L",
	"2.5.4.10": "O",
	"2.5.4.11": "OU",
	"2.5.4.3":  "CN",
}

func OidString(oid asn1.ObjectIdentifier) string {
	res := ""
	for _, num := range oid {
		if res != "" {
			res += "."
		}
		res += strconv.FormatInt(int64(num), 10)
	}
	return res
}

func PrettyOid(oidString string) string {
	prettyString := OidMap[oidString]
	if prettyString != "" {
		return prettyString
	} else {
		return oidString
	}
}

func PkixTypeValueString(typeValue pkix.AttributeTypeAndValue) string {
	return fmt.Sprintf("%s=%s", PrettyOid(OidString(typeValue.Type)), typeValue.Value)
}

func PkixNameString(name *pkix.Name) string {
	result := make([]string, 0, len(name.Names))
	for i := len(name.Names) - 1; i >= 0; i-- {
		typeValue := name.Names[i]
		result = append(result, PkixTypeValueString(typeValue))
	}
	return strings.Join(result, ", ")
}
