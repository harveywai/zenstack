package main

import (
	"fmt"
	"os" // import os package

	"github.com/harveywai/zenstack/pkg/providers/domain"
)

func main() {
	fmt.Println("🚀 ZenStack Asset Scanner starting...")

	// from environment variables
	ak := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_ID")
	sk := os.Getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET")

	if ak == "" || sk == "" {
		fmt.Println("❌ Error: Please set ALIBABA_CLOUD_ACCESS_KEY_ID and SECRET env vars")
		return
	}

	p := &domain.AliyunProvider{
		AccessKey: ak,
		SecretKey: sk,
		Region:    "cn-hangzhou",
	}

	assets, err := p.FetchDomains()
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
		return
	}

	for _, a := range assets {
		fmt.Printf("🌐 Domain: %s | SSL Expires: %d days\n", a.DomainName, a.DaysRemaining)
	}
}
