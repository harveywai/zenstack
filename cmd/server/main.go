package main

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/harveywai/zenstack/pkg/providers/domain"
)

const (
	// workerPoolSize defines the number of concurrent workers
	workerPoolSize = 5
	// criticalThreshold defines the days remaining threshold for critical status
	criticalThreshold = 7
	// warningThreshold defines the days remaining threshold for warning status
	warningThreshold = 30
)

// ScanResultWithStatus extends ScanResult with security status information
type ScanResultWithStatus struct {
	domain.ScanResult
	Status string `json:"status"`
}

// ScanResponse represents the API response structure
type ScanResponse struct {
	Results []ScanResultWithStatus `json:"results"`
	Summary SummaryInfo            `json:"summary"`
}

// SummaryInfo contains summary statistics
type SummaryInfo struct {
	TotalScanned int `json:"total_scanned"`
	AtRisk       int `json:"at_risk"`
}

func main() {
	// Initialize Gin router
	r := gin.Default()

	// Serve HTML dashboard at root
	r.GET("/", handleDashboard)

	// Register API routes
	v1 := r.Group("/v1")
	{
		v1.GET("/scan", handleScan)
	}

	// Start server
	r.Run(":8080")
}

// handleDashboard serves the HTML dashboard for the Internal Developer Platform
func handleDashboard(c *gin.Context) {
	// HTML uses Tailwind CSS via CDN and a small amount of JavaScript
	// to call the /v1/scan API and render results in the browser.
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ZenStack - Certificate Scanner</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
    <div class="min-h-screen flex flex-col">
        <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
            <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
                <div class="flex items-center gap-3">
                    <div class="h-8 w-8 rounded-lg bg-emerald-500 flex items-center justify-center text-slate-950 font-black">
                        Z
                    </div>
                    <div>
                        <h1 class="text-lg font-semibold tracking-tight">ZenStack – Internal Developer Platform</h1>
                        <p class="text-xs text-slate-400">Remote TLS Certificate Health Dashboard</p>
                    </div>
                </div>
                <div class="hidden sm:flex items-center gap-3 text-xs text-slate-400">
                    <span class="inline-flex items-center gap-1">
                        <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        Live Scanner
                    </span>
                </div>
            </div>
        </header>

        <main class="flex-1">
            <div class="max-w-6xl mx-auto px-4 py-8 space-y-6">
                <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                    <div class="flex items-center justify-between gap-4 flex-wrap">
                        <div>
                            <h2 class="text-base font-semibold tracking-tight">Certificate Risk Scanner</h2>
                            <p class="text-xs text-slate-400 mt-1">
                                Enter one or more domains and ZenStack will run a concurrent TLS certificate health check.
                            </p>
                        </div>
                    </div>

                    <div class="mt-4 grid gap-3 md:grid-cols-[minmax(0,1.8fr)_minmax(0,0.9fr)] items-end">
                        <div class="space-y-1">
                            <label for="domains-input" class="block text-xs font-medium text-slate-300">
                                Domains (comma-separated)
                            </label>
                            <textarea
                                id="domains-input"
                                rows="2"
                                class="w-full rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 shadow-inner shadow-black/40 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70 transition"
                                placeholder="example.com, github.com, internal.mycompany.com"
                            ></textarea>
                            <p class="text-[11px] text-slate-500">
                                Tip: You can paste a comma-separated list from your monitoring or inventory systems.
                            </p>
                        </div>

                        <div class="flex flex-col items-stretch gap-2">
                            <button
                                id="scan-button"
                                class="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-sm font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed transition"
                            >
                                <span id="scan-button-label">Scan</span>
                                <svg
                                    id="scan-spinner"
                                    class="hidden h-4 w-4 animate-spin text-slate-950"
                                    xmlns="http://www.w3.org/2000/svg"
                                    fill="none"
                                    viewBox="0 0 24 24"
                                >
                                    <circle
                                        class="opacity-25"
                                        cx="12"
                                        cy="12"
                                        r="10"
                                        stroke="currentColor"
                                        stroke-width="4"
                                    ></circle>
                                    <path
                                        class="opacity-75"
                                        fill="currentColor"
                                        d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z"
                                    ></path>
                                </svg>
                            </button>
                            <p id="scan-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                        </div>
                    </div>
                </section>

                <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                    <div class="flex items-center justify-between gap-3 flex-wrap">
                        <div>
                            <h3 class="text-sm font-semibold tracking-tight">Scan Results</h3>
                            <p class="text-xs text-slate-400" id="summary-text">
                                No scans yet. Run a scan to see certificate status, expiry, and issuers.
                            </p>
                        </div>
                        <div class="flex items-center gap-2 text-[11px] text-slate-400">
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800/80 border border-slate-700/80">
                                <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
                                OK
                            </span>
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800/80 border border-slate-700/80">
                                <span class="h-2 w-2 rounded-full bg-amber-400"></span>
                                Warning
                            </span>
                            <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-slate-800/80 border border-slate-700/80">
                                <span class="h-2 w-2 rounded-full bg-red-500"></span>
                                Critical / Expired
                            </span>
                        </div>
                    </div>

                    <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                        <table class="min-w-full divide-y divide-slate-800 text-sm">
                            <thead class="bg-slate-900/80">
                                <tr>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Domain</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">SSL Expiry (browser local time)</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Days Remaining</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Issuer</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Registrar</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Domain Expiry (browser local time)</th>
                                    <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Name Servers</th>
                                </tr>
                            </thead>
                            <tbody id="results-body" class="divide-y divide-slate-900/80">
                                <tr>
                                    <td colspan="8" class="px-3 py-6 text-center text-xs text-slate-500">
                                        No data yet. Run a scan to populate this table.
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </section>
            </div>
        </main>

        <footer class="border-t border-slate-800 bg-slate-900/80">
            <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between text-[11px] text-slate-500">
                <span>ZenStack · Internal Developer Platform</span>
                <span>TLS Certificate Scanner · Local environment</span>
            </div>
        </footer>
    </div>

    <script>
        // Helper to map status to Tailwind color classes
        function statusBadgeClasses(status) {
            const base = "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium";
            switch (status) {
                case "Expired":
                case "Critical":
                    return base + " bg-red-500/10 text-red-400 border border-red-500/40";
                case "Warning":
                    return base + " bg-amber-400/10 text-amber-300 border border-amber-400/40";
                case "Offline":
                    return base + " bg-slate-700/60 text-slate-300 border border-slate-600/60";
                default:
                    return base + " bg-emerald-500/10 text-emerald-300 border border-emerald-500/40";
            }
        }

        async function runScan() {
            const input = document.getElementById("domains-input");
            const button = document.getElementById("scan-button");
            const spinner = document.getElementById("scan-spinner");
            const label = document.getElementById("scan-button-label");
            const errorEl = document.getElementById("scan-error");
            const tbody = document.getElementById("results-body");
            const summaryText = document.getElementById("summary-text");

            const raw = (input.value || "").trim();
            errorEl.textContent = "";

            if (!raw) {
                errorEl.textContent = "Please provide at least one domain.";
                return;
            }

            // Build query string
            const params = new URLSearchParams();
            params.set("domains", raw);

            // Set loading state
            button.disabled = true;
            spinner.classList.remove("hidden");
            label.textContent = "Scanning...";

            try {
                const resp = await fetch("/v1/scan?" + params.toString(), {
                    method: "GET",
                    headers: {
                        "Accept": "application/json",
                    },
                });

                if (!resp.ok) {
                    let message = "Scan failed with status " + resp.status;
                    try {
                        const body = await resp.json();
                        if (body && body.error) {
                            message = body.error;
                        }
                    } catch (_) {}
                    throw new Error(message);
                }

                const data = await resp.json();

                const results = Array.isArray(data.results) ? data.results : [];
                const summary = data.summary || {};

                if (!results.length) {
                    tbody.innerHTML = '<tr><td colspan="8" class="px-3 py-6 text-center text-xs text-slate-500">No results returned from the scanner.</td></tr>';
                    summaryText.textContent = "No results. Try adding more domains or check connectivity.";
                    return;
                }

                tbody.innerHTML = "";
                for (const item of results) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    const domainCell = document.createElement("td");
                    domainCell.className = "px-3 py-2 text-xs font-medium text-slate-100";
                    domainCell.textContent = item.domain_name || "-";

                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const status = item.status || "Unknown";
                    const badge = document.createElement("span");
                    badge.className = statusBadgeClasses(status);
                    badge.textContent = status;
                    statusCell.appendChild(badge);

                    const expiryCell = document.createElement("td");
                    expiryCell.className = "px-3 py-2 text-xs text-slate-200";
                    // Important: use browser local timezone for display of SSL expiry
                    if (item.expiry_date) {
                        const dt = new Date(item.expiry_date);
                        expiryCell.textContent = dt.toLocaleString();
                    } else if (item.expiry_date_human) {
                        expiryCell.textContent = item.expiry_date_human;
                    } else {
                        expiryCell.textContent = "-";
                    }

                    const daysCell = document.createElement("td");
                    daysCell.className = "px-3 py-2 text-xs text-slate-200";
                    daysCell.textContent = typeof item.days_remaining === "number" ? item.days_remaining : "-";

                    const issuerCell = document.createElement("td");
                    issuerCell.className = "px-3 py-2 text-xs text-slate-300";
                    issuerCell.textContent = item.issuer || "-";

                    const registrarCell = document.createElement("td");
                    registrarCell.className = "px-3 py-2 text-xs text-slate-300";
                    registrarCell.textContent = item.registrar || "-";

                    const domainExpiryCell = document.createElement("td");
                    domainExpiryCell.className = "px-3 py-2 text-xs text-slate-200";
                    if (item.domain_expiry_date) {
                        const d = new Date(item.domain_expiry_date);
                        const localeString = d.toLocaleString();

                        // Highlight domain expiry in orange if within 60 days
                        const now = new Date();
                        const diffMs = d.getTime() - now.getTime();
                        const diffDays = diffMs / (1000 * 60 * 60 * 24);
                        if (diffDays >= 0 && diffDays <= 60) {
                            domainExpiryCell.className = "px-3 py-2 text-xs text-amber-300";
                        }

                        domainExpiryCell.textContent = localeString;
                    } else {
                        domainExpiryCell.textContent = "-";
                    }

                    const nsCell = document.createElement("td");
                    nsCell.className = "px-3 py-2 text-xs text-slate-300";
                    if (Array.isArray(item.name_servers) && item.name_servers.length > 0) {
                        nsCell.textContent = item.name_servers.join(", ");
                    } else {
                        nsCell.textContent = "-";
                    }

                    tr.appendChild(domainCell);
                    tr.appendChild(statusCell);
                    tr.appendChild(expiryCell);
                    tr.appendChild(daysCell);
                    tr.appendChild(issuerCell);
                    tr.appendChild(registrarCell);
                    tr.appendChild(domainExpiryCell);
                    tr.appendChild(nsCell);

                    tbody.appendChild(tr);
                }

                const total = typeof summary.total_scanned === "number" ? summary.total_scanned : results.length;
                const atRisk = typeof summary.at_risk === "number" ? summary.at_risk : 0;
                summaryText.textContent = "Scanned " + total + " domains • At risk: " + atRisk;
            } catch (err) {
                console.error(err);
                errorEl.textContent = err.message || "Unexpected error while running scan.";
            } finally {
                // Reset loading state
                button.disabled = false;
                spinner.classList.add("hidden");
                label.textContent = "Scan";
            }
        }

        document.getElementById("scan-button").addEventListener("click", function () {
            runScan();
        });

        document.getElementById("domains-input").addEventListener("keydown", function (event) {
            if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                event.preventDefault();
                runScan();
            }
        });
    </script>
</body>
</html>`

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// handleScan processes the scan request
func handleScan(c *gin.Context) {
	// Get domains from query parameter
	domainsParam := c.Query("domains")
	if domainsParam == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "domains parameter is required",
		})
		return
	}

	// Parse comma-separated domains
	domains := parseDomains(domainsParam)
	if len(domains) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "at least one valid domain is required",
		})
		return
	}

	// Perform concurrent scanning using worker pool
	scanResults := scanDomains(domains)

	// Add status information to results
	resultsWithStatus := make([]ScanResultWithStatus, 0, len(scanResults))
	atRiskCount := 0

	for _, result := range scanResults {
		status := getStatus(result)
		if status == "Warning" || status == "Critical" || status == "Expired" {
			atRiskCount++
		}

		// Print colored status to console
		printResult(result, status)

		resultsWithStatus = append(resultsWithStatus, ScanResultWithStatus{
			ScanResult: result,
			Status:     status,
		})
	}

	// Print summary information
	printSummary(len(scanResults), atRiskCount)

	// Return results as JSON
	c.JSON(http.StatusOK, ScanResponse{
		Results: resultsWithStatus,
		Summary: SummaryInfo{
			TotalScanned: len(scanResults),
			AtRisk:       atRiskCount,
		},
	})
}

// parseDomains splits comma-separated domain string and trims whitespace
func parseDomains(domainsParam string) []string {
	parts := strings.Split(domainsParam, ",")
	var domains []string
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			domains = append(domains, trimmed)
		}
	}
	return domains
}

// scanDomains performs concurrent scanning using worker pool pattern
func scanDomains(domains []string) []domain.ScanResult {
	// Create channels for job distribution and result collection
	jobs := make(chan string, len(domains))
	results := make(chan domain.ScanResult, len(domains))

	// Use WaitGroup to wait for all workers to complete
	var wg sync.WaitGroup

	// Start worker pool
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	// Send all jobs to the jobs channel
	for _, host := range domains {
		jobs <- host
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()
	close(results)

	// Collect results
	var scanResults []domain.ScanResult
	for result := range results {
		scanResults = append(scanResults, result)
	}

	return scanResults
}

// worker processes jobs from the jobs channel and sends results to the results channel
func worker(jobs <-chan string, results chan<- domain.ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()
	for host := range jobs {
		result := domain.CheckCertificate(host)
		results <- result
	}
}

// getStatus determines the security status based on days remaining
func getStatus(result domain.ScanResult) string {
	if !result.IsReachable {
		return "Offline"
	}

	// Check if certificate is expired (from domain package status)
	if result.Status == "Expired" {
		return "Expired"
	}

	// Apply security thresholds for valid certificates
	if result.DaysRemaining < criticalThreshold {
		return "Critical"
	}

	if result.DaysRemaining < warningThreshold {
		return "Warning"
	}

	return "OK"
}

// printResult prints scan result with colored status
func printResult(result domain.ScanResult, status string) {
	if !result.IsReachable {
		fmt.Printf("Domain: %s | Status: %s\n", result.DomainName, color.RedString("Offline"))
		return
	}

	var statusColor string
	switch status {
	case "Expired":
		statusColor = color.RedString("Expired")
	case "Critical":
		statusColor = color.RedString("Critical")
	case "Warning":
		statusColor = color.YellowString("Warning")
	default:
		statusColor = color.GreenString("OK")
	}

	fmt.Printf("Domain: %s | Status: %s | Days Remaining: %d | Issuer: %s\n",
		result.DomainName,
		statusColor,
		result.DaysRemaining,
		result.Issuer,
	)
}

// printSummary prints summary statistics with colored output
func printSummary(totalScanned, atRisk int) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	color.Cyan("Scan Summary:")
	fmt.Printf("Total Scanned: %d\n", totalScanned)
	if atRisk > 0 {
		color.Yellow("At Risk Domains: %d\n", atRisk)
	} else {
		color.Green("At Risk Domains: %d\n", atRisk)
	}
	fmt.Println(strings.Repeat("=", 60))
}
