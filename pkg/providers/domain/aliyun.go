package domain

import (
	"crypto/tls"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
)

// Asset defines the structure for our domain discovery
type Asset struct {
	DomainName    string    `json:"domain_name"`
	ExpiryDate    time.Time `json:"expiry_date"`
	DaysRemaining int       `json:"days_remaining"`
}

type AliyunProvider struct {
	AccessKey string
	SecretKey string
	Region    string
}

// FetchDomains gets list from Aliyun and checks SSL
func (p *AliyunProvider) FetchDomains() ([]Asset, error) {
	client, err := alidns.NewClientWithAccessKey(p.Region, p.AccessKey, p.SecretKey)
	if err != nil {
		return nil, err
	}

	request := alidns.CreateDescribeDomainsRequest()
	response, err := client.DescribeDomains(request)
	if err != nil {
		return nil, err
	}

	var assets []Asset
	for _, d := range response.Domains.Domain {
		expiry := getSSLExpiry(d.DomainName)
		assets = append(assets, Asset{
			DomainName:    d.DomainName,
			ExpiryDate:    expiry,
			DaysRemaining: int(time.Until(expiry).Hours() / 24),
		})
	}
	return assets, nil
}

// Helper to check TLS certificate expiration
func getSSLExpiry(domain string) time.Time {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return time.Time{}
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0].NotAfter
}