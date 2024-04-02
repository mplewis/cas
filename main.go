package main

import (
	"fmt"

	"github.com/mplewis/cas/lib/dns"
	"github.com/mplewis/cas/lib/sig"
)

var secret = []byte("rosebud")

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func fakeTxtRecordClient(domain string) ([]string, error) {
	return []string{
		"did:cas:v1:I1rM1ZCONGQPE2Pxi0kthID0XGlUtrXz_Q--RKxoS_4",
		"did:cas:v1:Rpqd7-ddVd3q_EgVGlUbUMVQuNQwUSA0xEA0_BXWMS0",
		"did:cas:v1:ghi789",
		"did:cas:v1:xyz123",
	}, nil
}

func main() {
	fmt.Println(sig.NewDIDSig(secret, []byte("user1")))
	fmt.Println(sig.NewDIDSig(secret, []byte("user2")))

	c := dns.NewClient(fakeTxtRecordClient)
	sigs := must(c.DidCasSigs("example.com"))
	for _, s := range sigs {
		fmt.Printf("%s: %t\n", s, sig.VerifyDIDSig(secret, []byte("user1"), s))
	}
}
