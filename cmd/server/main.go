package main

import (
	"fmt"
	"github.com/harveywai/zenstack/pkg/providers/domain"
)

func main() {
	fmt.Println("🚀 ZenStack Asset Scanner starting...")

	// Note: Use environment variables in production!
	p := &domain.AliyunProvider{
		AccessKey: "YOUR_ACCESS_KEY",
		SecretKey: "YOUR_SECRET_KEY",
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