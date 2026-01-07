package domain

import (
	"crypto/tls"
	"log"
	"math"
	"net"
	"strings"
	"time"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

// ScanResult represents the gathered information for a single domain
type ScanResult struct {
	DomainName       string    `json:"domain_name"`
	ExpiryDate       time.Time `json:"expiry_date"`
	ExpiryDateHuman  string    `json:"expiry_date_human"`
	DaysRemaining    int       `json:"days_remaining"`
	IsReachable      bool      `json:"is_reachable"`
	Issuer           string    `json:"issuer"`
	Status           string    `json:"status"`
	Registrar        string    `json:"registrar"`
	DomainExpiryDate time.Time `json:"domain_expiry_date"`
	NameServers      []string  `json:"name_servers"`
}

// CheckCertificate performs a TLS handshake to extract SSL/TLS metadata
func CheckCertificate(domain string) ScanResult {
	// Set a connection timeout to prevent hanging
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	// Connect to port 443 (HTTPS)
	// InsecureSkipVerify is set to true to fetch info even if the cert is expired
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return ScanResult{
			DomainName:  domain,
			IsReachable: false,
		}
	}
	defer conn.Close()

	// Get the first certificate in the peer chain
	cert := conn.ConnectionState().PeerCertificates[0]

	// Convert expiry time to local time zone so that JSON output matches system clock
	expiryUTC := cert.NotAfter
	expiryLocal := expiryUTC.In(time.Local)

	// Calculate days remaining using math.Ceil for more intuitive countdown
	// For example, 205.5 days will be represented as 206 days
	daysRemaining := int(math.Ceil(time.Until(expiryLocal).Hours() / 24))

	// Determine status based on days remaining
	status := "Valid"
	if daysRemaining < 0 {
		status = "Expired"
	}

	// Collect WHOIS information (registrar, domain expiration date, and name servers)
	registrar, domainExpiry, nameServers := GetWhoisInfo(domain)

	return ScanResult{
		DomainName:       domain,
		ExpiryDate:       expiryLocal,
		ExpiryDateHuman:  expiryLocal.Format("2006-01-02 15:04:05"),
		DaysRemaining:    daysRemaining,
		IsReachable:      true,
		Issuer:           cert.Issuer.Organization[0],
		Status:           status,
		Registrar:        registrar,
		DomainExpiryDate: domainExpiry,
		NameServers:      nameServers,
	}
}

// GetWhoisInfo fetches registrar, domain expiration information, and name servers using WHOIS and DNS.
// It returns the registrar name, the domain expiration date (renewal date), and a list of name servers.
// If WHOIS or DNS lookups fail, empty values are returned and errors are logged.
func GetWhoisInfo(domain string) (string, time.Time, []string) {
	// Derive the root domain (registrable domain) for WHOIS lookup.
	// Example: "api.internal.example.co.uk" -> "example.co.uk".
	rootDomain := domain
	if dn, err := publicsuffix.Parse(domain); err == nil {
		// Domain is the registrable part: e.g., "example.co.uk"
		if dn.SLD != "" && dn.TLD != "" {
			rootDomain = dn.SLD + "." + dn.TLD
		}
	}

	raw, err := whois.Whois(rootDomain)
	if err != nil {
		log.Printf("WHOIS lookup failed for %s: %v", rootDomain, err)
		return "", time.Time{}, nil
	}

	parsed, err := whoisparser.Parse(raw)
	if err != nil {
		log.Printf("WHOIS parse failed for %s: %v", rootDomain, err)
		return "", time.Time{}, nil
	}

	registrar := ""
	if parsed.Registrar.Name != "" {
		registrar = parsed.Registrar.Name
	} else {
		log.Printf("WHOIS registrar not found for %s", rootDomain)
	}

	// Domain.ExpirationDate is usually in a normalized string format, often RFC3339.
	// We try to parse it; if parsing fails, a zero time is returned.
	var domainExpiry time.Time
	if parsed.Domain.ExpirationDate != "" {
		// Try common layouts; start with RFC3339.
		layouts := []string{
			time.RFC3339,
			"2006-01-02T15:04:05Z",
			"2006-01-02 15:04:05 MST",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, parsed.Domain.ExpirationDate); err == nil {
				domainExpiry = t
				break
			}
		}
		if domainExpiry.IsZero() {
			log.Printf("WHOIS expiration date parse failed for %s: %q", rootDomain, parsed.Domain.ExpirationDate)
		}
	} else {
		log.Printf("WHOIS expiration date not found for %s", rootDomain)
	}

	// Extract name servers if available; fall back to DNS if WHOIS is missing them.
	var nameServers []string

	if len(parsed.Domain.NameServers) > 0 {
		for _, ns := range parsed.Domain.NameServers {
			host := strings.TrimSpace(ns)
			// Remove trailing dot that some sources include.
			host = strings.TrimSuffix(host, ".")
			if host != "" {
				nameServers = append(nameServers, host)
			}
		}
	} else {
		log.Printf("WHOIS name servers not found for %s, falling back to DNS NS lookup", rootDomain)
		nsRecords, err := net.LookupNS(rootDomain)
		if err != nil {
			log.Printf("DNS NS lookup failed for %s: %v", rootDomain, err)
		} else {
			for _, r := range nsRecords {
				host := strings.TrimSpace(r.Host)
				host = strings.TrimSuffix(host, ".")
				if host != "" {
					nameServers = append(nameServers, host)
				}
			}
			if len(nameServers) == 0 {
				log.Printf("DNS NS lookup for %s returned no usable name servers", rootDomain)
			}
		}
	}

	return registrar, domainExpiry, nameServers
}
