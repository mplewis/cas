package main

import (
	"fmt"

	"github.com/mplewis/cas/lib/dns"
)

func fakeTxtRecordClient(domain string) ([]string, error) {
	return []string{
		"did:cas:v1:abc123",
		"did:cas:v1:def456",
		"did:cas:v1:ghi789",
		"did:cas:v1:xyz123",
	}, nil
}

func main() {
	c := dns.NewClient(fakeTxtRecordClient)
	fmt.Println(c.DidCasSigs("example.com"))
}
