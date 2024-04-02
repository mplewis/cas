package sig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const CAS_FORMAT = "did:cas:v1:%s"

func NewDIDSig(secret []byte, id []byte) string {
	hash := hmac.New(sha256.New, secret)
	hash.Write(id)
	sum := hash.Sum(nil)
	b64 := base64.RawURLEncoding.EncodeToString(sum)
	sig := fmt.Sprintf(CAS_FORMAT, b64)
	fmt.Println(secret, id, sig)
	return sig
}

func VerifyDIDSig(secret []byte, id []byte, sig string) bool {
	return sig == NewDIDSig(secret, id)
}
