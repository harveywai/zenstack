package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// EndpointMetadata represents a single API endpoint extracted from an OpenAPI/Swagger document.
type EndpointMetadata struct {
	Path    string `json:"path"`
	Method  string `json:"method"`
	Summary string `json:"summary,omitempty"`
}

// APIDoc holds the parsed API specification and derived endpoint metadata.
type APIDoc struct {
	ServiceURL string                     `json:"service_url"`
	Spec       map[string]any             `json:"spec"`
	Endpoints  []EndpointMetadata         `json:"endpoints"`
	FetchedAt  time.Time                  `json:"fetched_at"`
}

var (
	docsMu        sync.RWMutex
	docsByService = make(map[string]*APIDoc)
	httpClient    = &http.Client{
		Timeout: 10 * time.Second,
	}
)

// FetchServiceDocs fetches and parses the OpenAPI/Swagger specification for the given service URL.
// It tries well-known paths such as /swagger.json and /openapi.json.
// The parsed specification and derived endpoint metadata are cached in memory.
func FetchServiceDocs(serviceURL string) (*APIDoc, error) {
	serviceURL = strings.TrimSpace(serviceURL)
	if serviceURL == "" {
		return nil, errors.New("service URL is required")
	}

	// Return cached document if available.
	docsMu.RLock()
	if doc, ok := docsByService[serviceURL]; ok {
		docsMu.RUnlock()
		return doc, nil
	}
	docsMu.RUnlock()

	spec, err := fetchOpenAPISpec(serviceURL)
	if err != nil {
		return nil, err
	}

	endpoints := extractEndpoints(spec)

	doc := &APIDoc{
		ServiceURL: serviceURL,
		Spec:       spec,
		Endpoints:  endpoints,
		FetchedAt:  time.Now(),
	}

	docsMu.Lock()
	docsByService[serviceURL] = doc
	docsMu.Unlock()

	return doc, nil
}

// fetchOpenAPISpec attempts to download and parse an OpenAPI/Swagger JSON spec from the service.
func fetchOpenAPISpec(serviceURL string) (map[string]any, error) {
	paths := []string{
		"/swagger.json",
		"/openapi.json",
	}

	var lastErr error

	for _, p := range paths {
		url := strings.TrimRight(serviceURL, "/") + p

		resp, err := httpClient.Get(url)
		if err != nil {
			lastErr = fmt.Errorf("request failed for %s: %w", url, err)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("non-success status %d for %s", resp.StatusCode, url)
			_ = resp.Body.Close()
			continue
		}

		var spec map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&spec); err != nil {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode JSON from %s: %w", url, err)
			continue
		}
		_ = resp.Body.Close()
		return spec, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no OpenAPI/Swagger document found for %s", serviceURL)
	}
	return nil, lastErr
}

// extractEndpoints builds a simple list of endpoints from an OpenAPI/Swagger spec.
// This is purely for internal metadata and does not modify the original spec.
func extractEndpoints(spec map[string]any) []EndpointMetadata {
	var endpoints []EndpointMetadata

	rawPaths, ok := spec["paths"].(map[string]any)
	if !ok {
		return endpoints
	}

	for path, v := range rawPaths {
		methods, ok := v.(map[string]any)
		if !ok {
			continue
		}
		for method, mv := range methods {
			normalizedMethod := strings.ToUpper(method)

			var summary string
			if mObj, ok := mv.(map[string]any); ok {
				if s, ok := mObj["summary"].(string); ok {
					summary = s
				}
			}

			endpoints = append(endpoints, EndpointMetadata{
				Path:    path,
				Method:  normalizedMethod,
				Summary: summary,
			})
		}
	}

	return endpoints
}

