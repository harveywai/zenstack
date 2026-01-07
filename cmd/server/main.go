package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/harveywai/zenstack/pkg/auth"
	"github.com/harveywai/zenstack/pkg/catalog"
	"github.com/harveywai/zenstack/pkg/database"
	"github.com/harveywai/zenstack/pkg/infra"
	"github.com/harveywai/zenstack/pkg/middleware"
	"github.com/harveywai/zenstack/pkg/providers/domain"
	"github.com/harveywai/zenstack/pkg/scaffolder"
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
	// Initialize database connection and run migrations.
	if err := database.Init(); err != nil {
		log.Fatalf("failed to initialize database: %v", err)
	}

	// Seed default admin user if no users exist.
	if err := database.SeedAdmin(); err != nil {
		log.Fatalf("failed to seed default admin user: %v", err)
	}

	// Initialize Gin router
	r := gin.Default()

	// Serve HTML dashboard at root
	r.GET("/", handleDashboard)

	// Public authentication routes (no AuthMiddleware applied)
	authPublic := r.Group("/v1/auth")
	{
		authPublic.POST("/login", handleLogin)
	}

	// Protected API routes
	v1 := r.Group("/v1")
	v1.Use(middleware.AuthMiddleware())
	{
		v1.GET("/scan", handleScan)
		v1.POST("/projects", handleCreateProject)
		v1.GET("/projects", handleListProjects)
		v1.GET("/infra/options", handleInfraOptions)
		v1.POST("/infra/provision", handleInfraProvision)
		v1.GET("/infra/status", handleInfraStatus)
		v1.GET("/infra", handleInfraList)
		v1.GET("/catalog/:serviceId/docs", handleCatalogDocs)
	}

	// Admin-only management routes
	v1Admin := r.Group("/v1/admin")
	v1Admin.Use(middleware.AuthMiddleware(), middleware.RoleMiddleware("admin"))
	{
		v1Admin.GET("/users/pending", handleListPendingUsers)
		v1Admin.GET("/users", handleListAllUsers)
		v1Admin.POST("/users", handleCreateUser)
		v1Admin.POST("/users/:id/approve", handleApproveUser)
		v1Admin.POST("/users/:id/reject", handleRejectUser)
	}

	// Start server
	r.Run(":8080")
}

// handleDashboard serves the HTML dashboard for the Internal Developer Platform
func handleDashboard(c *gin.Context) {
	// HTML uses Tailwind CSS via CDN and a small amount of JavaScript
	// to call the backend APIs and render results in the browser.
	const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>ZenStack - Internal Developer Platform</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-slate-950 text-slate-100">
    <div class="min-h-screen flex bg-slate-950 text-slate-100">
        <!-- Sidebar Navigation -->
        <aside class="w-60 border-r border-slate-800 bg-slate-950/95 flex flex-col">
            <div class="px-4 py-4 border-b border-slate-800 flex items-center gap-3">
                <div class="h-9 w-9 rounded-xl bg-emerald-500 flex items-center justify-center text-slate-950 font-black">
                    Z
                </div>
                <div>
                    <p class="text-sm font-semibold tracking-tight">ZenStack</p>
                    <p class="text-[11px] text-slate-400">Internal Developer Platform</p>
                </div>
            </div>
            <nav class="flex-1 px-3 py-4 space-y-1 text-sm">
                <button
                    id="nav-assets"
                    data-view="assets"
                    class="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 text-slate-50 font-medium"
                >
                    <span class="h-2 w-2 rounded-full bg-emerald-400"></span>
                    Assets
                </button>
                <button
                    id="nav-catalog"
                    data-view="catalog"
                    class="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-300 hover:bg-slate-800/60"
                >
                    <span class="h-2 w-2 rounded-full bg-sky-400"></span>
                    Catalog
                </button>
                <button
                    id="nav-infra"
                    data-view="infra"
                    class="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-300 hover:bg-slate-800/60"
                >
                    <span class="h-2 w-2 rounded-full bg-amber-400"></span>
                    Infrastructure
                </button>
                <button
                    id="nav-users"
                    data-view="users"
                    class="hidden w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-300 hover:bg-slate-800/60"
                >
                    <span class="h-2 w-2 rounded-full bg-rose-400"></span>
                    User Management
                </button>
            </nav>
            <div class="px-4 py-3 border-t border-slate-800 text-[11px] text-slate-500 space-y-1">
                <p>Environment: Local</p>
                <div class="flex items-center justify-between gap-2">
                    <div id="current-user" class="text-[11px] text-slate-400">
                        Not authenticated
                    </div>
                    <button
                        id="logout-button"
                        class="hidden rounded-md border border-slate-700 px-2 py-0.5 text-[10px] text-slate-200 hover:bg-slate-800/80"
                        type="button"
                    >
                        Logout
                    </button>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <div class="flex-1 flex flex-col">
            <header class="border-b border-slate-800 bg-slate-900/80 backdrop-blur">
                <div class="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div>
                        <h1 class="text-lg font-semibold tracking-tight">Internal Developer Platform</h1>
                        <p class="text-xs text-slate-400">Discover assets, launch services, and request infrastructure.</p>
                    </div>
                    <div class="hidden sm:flex items-center gap-3 text-xs text-slate-400">
                        <span class="inline-flex items-center gap-1">
                            <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
                            Control Plane Ready
                        </span>
                    </div>
                </div>
            </header>

            <main class="flex-1">
                <div class="max-w-6xl mx-auto px-4 py-8 space-y-6">
                    <!-- Assets View: Domain & SSL Scanner -->
                    <section id="view-assets" class="space-y-6">
                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                            <div class="flex items-center justify-between gap-4 flex-wrap">
                                <div>
                                    <h2 class="text-base font-semibold tracking-tight">Certificate Risk Scanner</h2>
                                    <p class="text-xs text-slate-400 mt-1">
                                        Enter one or more domains and ZenStack will run a concurrent TLS certificate and registrar health check.
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
                                        No scans yet. Run a scan to see certificate status, expiry, registrar, and name servers.
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
                    </section>

                    <!-- Catalog View: Software Catalog and Create Service -->
                    <section id="view-catalog" class="space-y-6 hidden">
                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-3">
                            <div class="flex items-center justify-between gap-4 flex-wrap">
                                <div>
                                    <h2 class="text-base font-semibold tracking-tight">Service Catalog</h2>
                                    <p class="text-xs text-slate-400 mt-1">
                                        Browse existing services and quickly bootstrap new workloads from templates.
                                    </p>
                                </div>
                                <button
                                    id="open-create-service"
                                    class="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 transition"
                                >
                                    <span class="text-sm">Create New Service</span>
                                </button>
                            </div>

                            <div class="mt-4 text-[11px] text-slate-400">
                                <p>This is a placeholder catalog. In a real setup, this would be backed by a Software Catalog source of truth.</p>
                            </div>
                        </section>

                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                            <div class="flex items-center justify-between gap-3 flex-wrap">
                                <div>
                                    <h3 class="text-sm font-semibold tracking-tight">Projects</h3>
                                    <p class="text-xs text-slate-400">
                                        Data is loaded from the <code class="text-slate-300">/v1/projects</code> API.
                                    </p>
                                </div>
                                <button
                                    id="refresh-projects"
                                    class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-slate-800/80"
                                >
                                    Refresh
                                </button>
                            </div>
                            <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                <table class="min-w-full divide-y divide-slate-800 text-sm">
                                    <thead class="bg-slate-900/80">
                                        <tr>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Name</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Template</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">GitHub</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody id="projects-body" class="divide-y divide-slate-900/80">
                                        <tr>
                                            <td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">
                                                Loading projects…
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    </section>

                    <!-- Infrastructure View: Databases -->
                    <section id="view-infra" class="space-y-6 hidden">
                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-3">
                            <div class="flex items-center justify-between gap-4 flex-wrap">
                                <div>
                                    <h2 class="text-base font-semibold tracking-tight">Database Provisioning</h2>
                                    <p class="text-xs text-slate-400 mt-1">
                                        Request managed database instances using T-shirt sizes. Crossplane integration will handle the actual provisioning.
                                    </p>
                                </div>
                            </div>
                        </section>

                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                            <div class="grid gap-4 md:grid-cols-[minmax(0,1.3fr)_minmax(0,1.1fr)]">
                                <form id="infra-form" class="space-y-3">
                                    <div>
                                        <label class="block text-xs font-medium text-slate-300" for="infra-name">
                                            Database Name
                                        </label>
                                        <input
                                            id="infra-name"
                                            type="text"
                                            class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                            placeholder="orders-db"
                                        />
                                    </div>

                                    <div>
                                        <label class="block text-xs font-medium text-slate-300" for="infra-engine">
                                            Engine
                                        </label>
                                        <select
                                            id="infra-engine"
                                            class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                        >
                                            <option value="Postgres">Postgres</option>
                                            <option value="MySQL">MySQL</option>
                                        </select>
                                    </div>

                                    <div>
                                        <label class="block text-xs font-medium text-slate-300" for="infra-size">
                                            Size
                                        </label>
                                        <select
                                            id="infra-size"
                                            class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                        >
                                            <option value="Small">Small</option>
                                            <option value="Medium">Medium</option>
                                            <option value="Large">Large</option>
                                        </select>
                                        <p class="text-[11px] text-slate-500 mt-1">
                                            Sizing: Small=1 vCPU/2GB, Medium=2 vCPU/4GB, Large=4 vCPU/8GB.
                                        </p>
                                    </div>

                                    <button
                                        id="infra-submit"
                                        type="button"
                                        class="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed transition"
                                    >
                                        Request Database
                                    </button>
                                    <p id="infra-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                                </form>

                                <div class="space-y-2 text-xs">
                                    <h3 class="text-sm font-semibold tracking-tight">Size Options</h3>
                                    <p class="text-[11px] text-slate-400">
                                        These options are returned by the <code class="text-slate-300">/v1/infra/options</code> API.
                                    </p>
                                    <ul id="infra-size-list" class="mt-2 space-y-1 text-[11px] text-slate-300">
                                        <li>Loading size options…</li>
                                    </ul>
                                    <div id="infra-last-request" class="mt-2 text-[11px] text-slate-400"></div>
                                    <div id="infra-last-status" class="mt-1 text-[11px] text-slate-400"></div>
                                </div>
                            </div>
                        </section>

                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                            <div class="flex items-center justify-between gap-3 flex-wrap">
                                <div>
                                    <h3 class="text-sm font-semibold tracking-tight">Infrastructure Resources</h3>
                                    <p class="text-xs text-slate-400">
                                        Data is loaded from the <code class="text-slate-300">/v1/infra</code> API.
                                    </p>
                                </div>
                                <div class="flex items-center gap-2">
                                    <button
                                        id="refresh-infra"
                                        class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-slate-800/80"
                                    >
                                        Refresh
                                    </button>
                                    <button
                                        id="refresh-infra-status"
                                        class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-slate-800/80"
                                    >
                                        Refresh Status
                                    </button>
                                </div>
                            </div>
                            <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                <table class="min-w-full divide-y divide-slate-800 text-sm">
                                    <thead class="bg-slate-900/80">
                                        <tr>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Resource</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Type</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Size</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                        </tr>
                                    </thead>
                                    <tbody id="infra-body" class="divide-y divide-slate-900/80">
                                        <tr>
                                            <td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">
                                                Loading infrastructure resources…
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </section>
                    </section>

                        <!-- User Management View: Admin only -->
                        <section id="view-users" class="space-y-6 hidden">
                            <div id="user-management-section" class="space-y-6">
                                <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-3">
                                <div class="flex items-center justify-between gap-4 flex-wrap">
                                    <div>
                                        <h2 class="text-base font-semibold tracking-tight">User Management</h2>
                                        <p class="text-xs text-slate-400 mt-1">
                                            Manage platform users and roles. Only administrators can access this view.
                                        </p>
                                    </div>
                                    <button
                                        id="open-add-user"
                                        class="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 transition hidden"
                                    >
                                        <span class="text-sm">Add User</span>
                                    </button>
                                </div>
                            </section>

                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div class="flex items-center justify-between gap-3 flex-wrap">
                                    <div>
                                        <h3 class="text-sm font-semibold tracking-tight">Users</h3>
                                        <p class="text-xs text-slate-400">
                                            Data is loaded from the <code class="text-slate-300">/v1/admin/users</code> API.
                                        </p>
                                    </div>
                                    <button
                                        id="refresh-users"
                                        class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-slate-800/80"
                                    >
                                        Refresh
                                    </button>
                                </div>
                                <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                    <table class="min-w-full divide-y divide-slate-800 text-sm">
                                        <thead class="bg-slate-900/80">
                                            <tr>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Username</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Role</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Created At</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="users-body" class="divide-y divide-slate-900/80">
                                            <tr>
                                                <td colspan="5" class="px-3 py-6 text-center text-xs text-slate-500">
                                                    Loading users…
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </section>
                            </div>
                        </section>
                </div>
            </main>

            <footer class="border-t border-slate-800 bg-slate-900/80">
                <div class="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between text-[11px] text-slate-500">
                    <span>ZenStack · Internal Developer Platform</span>
                    <span>Local environment · Prototype UI</span>
                </div>
            </footer>
        </div>
    </div>

    <!-- Login Overlay -->
    <div
        id="login-overlay"
        class="fixed inset-0 z-40 flex items-center justify-center bg-slate-950/90 backdrop-blur-sm"
    >
        <div class="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/60 p-6 space-y-4">
            <div class="space-y-1">
                <h2 id="auth-title" class="text-sm font-semibold tracking-tight">Sign in to ZenStack</h2>
                <p class="text-[11px] text-slate-400">
                    Use your platform credentials to access the Internal Developer Platform.
                </p>
            </div>
            <form id="login-form" class="space-y-3">
                <div>
                    <label for="login-username" class="block text-xs font-medium text-slate-300">Username</label>
                    <input
                        id="login-username"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="admin"
                    />
                </div>
                <div>
                    <label for="login-password" class="block text-xs font-medium text-slate-300">Password</label>
                    <input
                        id="login-password"
                        type="password"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="••••••••"
                    />
                </div>
                <p id="login-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                <button
                    id="login-submit"
                    type="submit"
                    class="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-3 py-2 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                >
                    <span id="login-submit-label">Sign In</span>
                </button>
                <p class="text-[10px] text-slate-500">
                    Default admin user: <code class="text-slate-300">admin / zenstack2026</code>
                </p>
            </form>
        </div>
    </div>

    <!-- Create Service Modal -->
    <div
        id="create-service-modal"
        class="fixed inset-0 hidden z-40 items-center justify-center bg-slate-950/70 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-md rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 p-5">
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Create New Service</h2>
                    <p class="text-[11px] text-slate-400">
                        ZenStack will scaffold a new repository from the selected template.
                    </p>
                </div>
                <button
                    id="create-service-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close modal"
                >
                    ✕
                </button>
            </div>

            <form id="create-service-form" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="svc-name">
                        Service Name
                    </label>
                    <input
                        id="svc-name"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="payments-service"
                    />
                </div>

                <div>
                    <label class="block text-xs font-medium text-slate-300" for="svc-template">
                        Template
                    </label>
                    <select
                        id="svc-template"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                    >
                        <option value="go-gin-starter">Go Gin Starter</option>
                    </select>
                    <p class="text-[11px] text-slate-500 mt-1">
                        Current implementation always uses the Go Gin Starter template.
                    </p>
                </div>

                <div>
                    <label class="block text-xs font-medium text-slate-300" for="svc-token">
                        GitHub Personal Access Token
                    </label>
                    <input
                        id="svc-token"
                        type="password"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="ghp_xxx..."
                    />
                    <p class="text-[11px] text-slate-500 mt-1">
                        Token is used only to create the repository on your GitHub account.
                    </p>
                </div>

                <div class="flex items-center justify-between gap-3 pt-1">
                    <p id="svc-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                    <div class="flex items-center gap-2">
                        <button
                            type="button"
                            id="svc-cancel"
                            class="rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800/80"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            id="svc-submit"
                            class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                        >
                            <span>Create</span>
                            <svg
                                id="svc-spinner"
                                class="hidden h-3 w-3 animate-spin text-slate-950"
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
                    </div>
                </div>
            </form>
        </div>
    </div>

    <!-- Add User Modal -->
    <div
        id="add-user-modal"
        class="fixed inset-0 hidden z-40 items-center justify-center bg-slate-950/70 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 p-6 space-y-4">
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Add User</h2>
                    <p class="text-[11px] text-slate-400">
                        Create a new user account. Users created by admins are automatically active.
                    </p>
                </div>
                <button
                    id="add-user-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close modal"
                >
                    ✕
                </button>
            </div>
            <form id="add-user-form" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="add-username">
                        Username
                    </label>
                    <input
                        id="add-username"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="username"
                        required
                    />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="add-password">
                        Password
                    </label>
                    <input
                        id="add-password"
                        type="password"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="••••••••"
                        required
                    />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="add-role">
                        Role
                    </label>
                    <select
                        id="add-role"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                    >
                        <option value="user">user</option>
                        <option value="admin">admin</option>
                    </select>
                </div>
                <p id="add-user-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                <div class="flex items-center justify-end gap-2">
                    <button
                        type="button"
                        id="add-user-cancel"
                        class="rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800/80"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        id="add-user-submit"
                        class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                        <span>Add User</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Swagger UI Modal -->
    <div
        id="swagger-modal"
        class="fixed inset-0 hidden z-30 items-center justify-center bg-slate-950/80 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-3xl h-[80vh] rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 flex flex-col">
            <div class="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Service API Documentation</h2>
                    <p id="swagger-service-label" class="text-[11px] text-slate-400"></p>
                </div>
                <button
                    id="swagger-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close Swagger modal"
                >
                    ✕
                </button>
            </div>
            <div id="swagger-container" class="flex-1 overflow-hidden bg-slate-950">
                <div id="swagger-ui" class="h-full w-full overflow-auto"></div>
            </div>
        </div>
    </div>

    <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
    <script>
        // Authentication helpers
        function getToken() {
            try {
                return localStorage.getItem("zenstack_token") || "";
            } catch (_) {
                return "";
            }
        }

        function getCurrentUser() {
            try {
                const raw = localStorage.getItem("zenstack_user");
                if (!raw) return null;
                return JSON.parse(raw);
            } catch (_) {
                return null;
            }
        }

        function saveAuth(token, user) {
            try {
                localStorage.setItem("zenstack_token", token || "");
                localStorage.setItem("zenstack_user", JSON.stringify(user || {}));
            } catch (_) {}
        }

        function clearAuth() {
            try {
                localStorage.removeItem("zenstack_token");
                localStorage.removeItem("zenstack_user");
            } catch (_) {}
        }

        function authHeaders(extra) {
            const headers = Object.assign({}, extra || {});
            const token = getToken();
            if (token) {
                headers["Authorization"] = "Bearer " + token;
            }
            return headers;
        }

        // Global fetch wrapper that automatically adds JWT token and handles auth errors
        async function apiFetch(url, options = {}) {
            const token = getToken();
            const headers = Object.assign({}, options.headers || {});
            
            // Automatically add Authorization header if token exists
            if (token) {
                headers["Authorization"] = "Bearer " + token;
            }

            // Merge headers into options
            const fetchOptions = Object.assign({}, options, { headers });

            try {
                const resp = await fetch(url, fetchOptions);
                
                // Handle 401 Unauthorized or 403 Forbidden by redirecting to login
                if (resp.status === 401 || resp.status === 403) {
                    clearAuth();
                    updateUserUI();
                    ensureAuthenticated();
                    // Show login overlay
                    const loginOverlay = document.getElementById("login-overlay");
                    if (loginOverlay) {
                        loginOverlay.classList.remove("hidden");
                        loginOverlay.classList.add("flex");
                    }
                    throw new Error("Authentication required. Please log in again.");
                }

                return resp;
            } catch (err) {
                // Re-throw to allow caller to handle
                throw err;
            }
        }

        // Public registration is disabled - only login is available

        function updateUserUI() {
            const userInfo = getCurrentUser();
            const currentUserEl = document.getElementById("current-user");
            const logoutBtn = document.getElementById("logout-button");
            const infraForm = document.getElementById("infra-form");
            const infraSubmit = document.getElementById("infra-submit");
            const navUsers = document.getElementById("nav-users");
            const addUserBtn = document.getElementById("open-add-user");

            if (!currentUserEl || !logoutBtn) return;

            if (!userInfo || !userInfo.username) {
                currentUserEl.textContent = "Not authenticated";
                logoutBtn.classList.add("hidden");
            } else {
                currentUserEl.textContent = "User: " + userInfo.username + " (" + (userInfo.role || "user") + ")";
                logoutBtn.classList.remove("hidden");
            }

            // UI permissions: limit infrastructure provisioning for non-admin users.
            const role = (userInfo && userInfo.role) || "user";
            if (infraSubmit) {
                if (role !== "admin") {
                    infraSubmit.disabled = true;
                    infraSubmit.classList.add("opacity-60", "cursor-not-allowed");
                } else {
                    infraSubmit.disabled = false;
                    infraSubmit.classList.remove("opacity-60", "cursor-not-allowed");
                }
            }
            if (infraForm) {
                if (role !== "admin") {
                    infraForm.classList.add("opacity-60");
                } else {
                    infraForm.classList.remove("opacity-60");
                }
            }

            // User Management navigation visibility: only show for admins.
            // Check localStorage directly for role as requested
            let storedRole = null;
            try {
                const userData = localStorage.getItem("zenstack_user");
                if (userData) {
                    const parsed = JSON.parse(userData);
                    storedRole = parsed ? parsed.role : null;
                }
            } catch (_) {}
            const isAdmin = storedRole === "admin" || role === "admin";
            
            if (navUsers) {
                if (isAdmin) {
                    navUsers.classList.remove("hidden");
                    navUsers.style.display = "";
                } else {
                    navUsers.classList.add("hidden");
                    navUsers.style.display = "none";
                }
            }
            if (addUserBtn) {
                if (role === "admin") {
                    addUserBtn.classList.remove("hidden");
                } else {
                    addUserBtn.classList.add("hidden");
                }
            }
        }

        function ensureAuthenticated() {
            const token = getToken();
            const user = getCurrentUser();
            const loginOverlay = document.getElementById("login-overlay");
            if (!loginOverlay) return;

            if (!token || !user || !user.username) {
                loginOverlay.classList.remove("hidden");
                loginOverlay.classList.add("flex");
            } else {
                loginOverlay.classList.add("hidden");
                loginOverlay.classList.remove("flex");
            }
        }

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

        // View switching for sidebar navigation
        function setActiveView(view) {
            const views = ["assets", "catalog", "infra", "users"];
            
            // Hide all sections first
            for (const v of views) {
                const section = document.getElementById("view-" + v);
                const btn = document.querySelector('[data-view="' + v + '"]');
                if (section) {
                    section.classList.add("hidden");
                    section.style.display = "none";
                }
                if (btn) {
                    btn.classList.remove("bg-slate-800", "text-slate-50", "font-medium");
                }
            }
            
            // Show the selected view
            const selectedSection = document.getElementById("view-" + view);
            const selectedBtn = document.querySelector('[data-view="' + view + '"]');
            if (selectedSection) {
                selectedSection.classList.remove("hidden");
                selectedSection.style.display = "";
            }
            if (selectedBtn) {
                selectedBtn.classList.add("bg-slate-800", "text-slate-50", "font-medium");
            }
            
            // Auto-load data when switching to specific views
            if (view === "users") {
                const userSection = document.getElementById("user-management-section");
                if (userSection) {
                    userSection.classList.remove("hidden");
                    userSection.style.display = "";
                }
                loadUsers();
            } else {
                const userSection = document.getElementById("user-management-section");
                if (userSection) {
                    userSection.classList.add("hidden");
                    userSection.style.display = "none";
                }
            }
            if (view === "catalog") {
                loadProjects();
            } else if (view === "infra") {
                loadInfraOptions();
                loadInfraResources();
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
                    headers: authHeaders({
                        "Accept": "application/json",
                    }),
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

        // Create Service modal helpers
        function openCreateServiceModal() {
            const modal = document.getElementById("create-service-modal");
            if (modal) {
                modal.classList.remove("hidden");
                modal.classList.add("flex");
            }
        }

        function closeCreateServiceModal() {
            const modal = document.getElementById("create-service-modal");
            if (modal) {
                modal.classList.add("hidden");
                modal.classList.remove("flex");
            }
            const errorEl = document.getElementById("svc-error");
            if (errorEl) errorEl.textContent = "";
        }

        async function submitCreateService(event) {
            event.preventDefault();
            const nameInput = document.getElementById("svc-name");
            const tokenInput = document.getElementById("svc-token");
            const errorEl = document.getElementById("svc-error");
            const submitBtn = document.getElementById("svc-submit");
            const spinner = document.getElementById("svc-spinner");

            errorEl.textContent = "";

            const projectName = (nameInput.value || "").trim();
            const githubToken = (tokenInput.value || "").trim();

            if (!projectName || !githubToken) {
                errorEl.textContent = "Service name and GitHub token are required.";
                return;
            }

            submitBtn.disabled = true;
            spinner.classList.remove("hidden");

            try {
                const resp = await fetch("/v1/projects", {
                    method: "POST",
                    headers: authHeaders({
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    }),
                    body: JSON.stringify({
                        project_name: projectName,
                        description: "Service created from ZenStack catalog",
                        github_token: githubToken,
                    }),
                });

                if (!resp.ok) {
                    let message = "Failed to create service (status " + resp.status + ")";
                    try {
                        const body = await resp.json();
                        if (body && body.error) {
                            message = body.error;
                        }
                    } catch (_) {}
                    throw new Error(message);
                }

                const data = await resp.json();
                closeCreateServiceModal();
                console.log("Service created:", data);
            } catch (err) {
                console.error(err);
                errorEl.textContent = err.message || "Unexpected error while creating service.";
            } finally {
                submitBtn.disabled = false;
                spinner.classList.add("hidden");
            }
        }

        // Infrastructure helpers
        async function loadInfraOptions() {
            const list = document.getElementById("infra-size-list");
            if (!list) return;
            try {
                const resp = await fetch("/v1/infra/options", {
                    method: "GET",
                    headers: authHeaders({ "Accept": "application/json" }),
                });
                if (!resp.ok) {
                    throw new Error("Failed to load infra options (status " + resp.status + ")");
                }
                const data = await resp.json();
                const sizes = Array.isArray(data.sizes) ? data.sizes : [];
                if (!sizes.length) {
                    list.innerHTML = "<li>No size options available.</li>";
                    return;
                }
                list.innerHTML = "";
                for (const s of sizes) {
                    const li = document.createElement("li");
                    li.textContent = s.name + " – " + s.vcpu + " vCPU / " + s.ram_gb + " GB RAM";
                    list.appendChild(li);
                }
            } catch (err) {
                console.error(err);
                list.innerHTML = "<li class='text-rose-400'>Failed to load size options.</li>";
            }
        }

        async function submitInfraProvision() {
            const name = (document.getElementById("infra-name").value || "").trim();
            const engine = (document.getElementById("infra-engine").value || "").trim();
            const size = (document.getElementById("infra-size").value || "").trim();
            const errorEl = document.getElementById("infra-error");
            const lastReq = document.getElementById("infra-last-request");
            const lastStatus = document.getElementById("infra-last-status");
            const button = document.getElementById("infra-submit");

            errorEl.textContent = "";

            if (!name || !engine || !size) {
                errorEl.textContent = "Name, engine, and size are required.";
                return;
            }

            button.disabled = true;

            try {
                const resp = await fetch("/v1/infra/provision", {
                    method: "POST",
                    headers: authHeaders({
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    }),
                    body: JSON.stringify({
                        name,
                        engine,
                        size,
                    }),
                });

                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    const msg = data && data.error ? data.error : "Provision request failed.";
                    throw new Error(msg);
                }

                lastReq.textContent = "Last request: " + JSON.stringify(data.resource || {}, null, 0);

                // Start polling for resource status using the tracked project name.
                const trackedName = (data && data.tracked_project_name) || name;
                if (trackedName) {
                    startInfraPolling(trackedName);
                    if (lastStatus) {
                        lastStatus.textContent = "Tracking resource status for project: " + trackedName;
                    }
                }
            } catch (err) {
                console.error(err);
                errorEl.textContent = err.message || "Unexpected error while requesting database.";
            } finally {
                button.disabled = false;
            }
        }

        // Load projects into the Catalog table.
        async function loadProjects() {
            const tbody = document.getElementById("projects-body");
            if (!tbody) return;
            try {
                const resp = await fetch("/v1/projects", {
                    method: "GET",
                    headers: authHeaders({ "Accept": "application/json" }),
                });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    throw new Error((data && data.error) || "Failed to load projects.");
                }
                const projects = Array.isArray(data.projects) ? data.projects : [];
                if (!projects.length) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No projects found.</td></tr>';
                    return;
                }
                tbody.innerHTML = "";
                for (const p of projects) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    const nameCell = document.createElement("td");
                    nameCell.className = "px-3 py-2 text-xs text-slate-100";
                    nameCell.textContent = p.name || "-";

                    const templateCell = document.createElement("td");
                    templateCell.className = "px-3 py-2 text-xs text-slate-300";
                    templateCell.textContent = p.template_type || "-";

                    const repoCell = document.createElement("td");
                    repoCell.className = "px-3 py-2 text-xs";
                    if (p.github_repo) {
                        const a = document.createElement("a");
                        a.href = p.github_repo;
                        a.target = "_blank";
                        a.rel = "noreferrer";
                        a.className = "text-emerald-400 hover:text-emerald-300 underline decoration-dotted";
                        a.textContent = "GitHub";
                        repoCell.appendChild(a);
                    } else {
                        repoCell.textContent = "-";
                    }

                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const badge = document.createElement("span");
                    badge.className = "inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/40";
                    badge.textContent = "Active";
                    statusCell.appendChild(badge);

                    tr.appendChild(nameCell);
                    tr.appendChild(templateCell);
                    tr.appendChild(repoCell);
                    tr.appendChild(statusCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error(err);
                tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-rose-400">Failed to load projects.</td></tr>';
            }
        }

        // Load infrastructure resource list.
        async function loadInfraResources() {
            const tbody = document.getElementById("infra-body");
            if (!tbody) return;
            try {
                const resp = await fetch("/v1/infra", {
                    method: "GET",
                    headers: authHeaders({ "Accept": "application/json" }),
                });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    throw new Error((data && data.error) || "Failed to load infrastructure resources.");
                }
                const resources = Array.isArray(data.resources) ? data.resources : [];
                if (!resources.length) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No infrastructure resources found.</td></tr>';
                    return;
                }
                tbody.innerHTML = "";
                for (const r of resources) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    const nameCell = document.createElement("td");
                    nameCell.className = "px-3 py-2 text-xs text-slate-100";
                    nameCell.textContent = r.resource_name || "-";

                    const typeCell = document.createElement("td");
                    typeCell.className = "px-3 py-2 text-xs text-slate-300";
                    typeCell.textContent = r.type || "-";

                    const sizeCell = document.createElement("td");
                    sizeCell.className = "px-3 py-2 text-xs text-slate-300";
                    sizeCell.textContent = r.size || "-";

                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const badge = document.createElement("span");
                    const status = (r.status || "Unknown").toString();
                    let classes =
                        "inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border ";
                    if (status === "Requested" || status === "Provisioning") {
                        classes += "bg-amber-500/10 text-amber-300 border-amber-500/40";
                    } else if (status === "Available") {
                        classes += "bg-emerald-500/10 text-emerald-300 border-emerald-500/40";
                    } else if (status === "Error") {
                        classes += "bg-red-500/10 text-red-400 border-red-500/40";
                    } else {
                        classes += "bg-slate-700/40 text-slate-200 border-slate-600/60";
                    }
                    badge.className = classes;
                    badge.textContent = status;
                    statusCell.appendChild(badge);

                    tr.appendChild(nameCell);
                    tr.appendChild(typeCell);
                    tr.appendChild(sizeCell);
                    tr.appendChild(statusCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error(err);
                tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-rose-400">Failed to load infrastructure resources.</td></tr>';
            }
        }

        // Load user list (admin only).
        async function loadUsers() {
            const tbody = document.getElementById("users-body");
            if (!tbody) return;
            try {
                const resp = await apiFetch("/v1/admin/users", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    throw new Error((data && data.error) || "Failed to load users.");
                }
                const users = Array.isArray(data.users) ? data.users : [];
                if (!users.length) {
                    tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-6 text-center text-xs text-slate-500">No users found.</td></tr>';
                    return;
                }
                const currentUser = getCurrentUser();
                const role = (currentUser && currentUser.role) || "user";
                tbody.innerHTML = "";
                for (const u of users) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    const nameCell = document.createElement("td");
                    nameCell.className = "px-3 py-2 text-xs text-slate-100";
                    nameCell.textContent = u.username || "-";

                    const roleCell = document.createElement("td");
                    roleCell.className = "px-3 py-2 text-xs text-slate-300";
                    roleCell.textContent = u.role || "-";

                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const statusText = (u.status || "pending").toString();
                    const badge = document.createElement("span");
                    let classes =
                        "inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium border ";
                    if (statusText === "active") {
                        classes += "bg-emerald-500/10 text-emerald-300 border-emerald-500/40";
                    } else if (statusText === "pending") {
                        classes += "bg-amber-500/10 text-amber-300 border-amber-500/40";
                    } else if (statusText === "disabled") {
                        classes += "bg-slate-700/60 text-slate-200 border-slate-600/70";
                    } else {
                        classes += "bg-slate-700/40 text-slate-200 border-slate-600/60";
                    }
                    badge.className = classes;
                    badge.textContent = statusText;
                    statusCell.appendChild(badge);

                    const createdCell = document.createElement("td");
                    createdCell.className = "px-3 py-2 text-xs text-slate-400";
                    createdCell.textContent = u.created_at || "";

                    const actionsCell = document.createElement("td");
                    actionsCell.className = "px-3 py-2 text-xs";
                    if (role === "admin" && statusText === "pending") {
                        const approveBtn = document.createElement("button");
                        approveBtn.className =
                            "inline-flex items-center px-2 py-0.5 mr-1 rounded-md border border-emerald-500/60 text-[11px] text-emerald-300 hover:bg-emerald-500/10";
                        approveBtn.textContent = "Approve";
                        approveBtn.addEventListener("click", async function () {
                            try {
                                const resp = await apiFetch("/v1/admin/users/" + u.id + "/approve", {
                                    method: "POST",
                                    headers: { "Accept": "application/json" },
                                });
                                const data = await resp.json().catch(() => ({}));
                                if (!resp.ok) {
                                    throw new Error((data && data.error) || "Failed to approve user.");
                                }
                                loadUsers();
                            } catch (err) {
                                console.error(err);
                                alert(err.message || "Failed to approve user.");
                            }
                        });

                        const rejectBtn = document.createElement("button");
                        rejectBtn.className =
                            "inline-flex items-center px-2 py-0.5 rounded-md border border-rose-500/60 text-[11px] text-rose-300 hover:bg-rose-500/10";
                        rejectBtn.textContent = "Reject";
                        rejectBtn.addEventListener("click", async function () {
                            try {
                                const resp = await apiFetch("/v1/admin/users/" + u.id + "/reject", {
                                    method: "POST",
                                    headers: { "Accept": "application/json" },
                                });
                                const data = await resp.json().catch(() => ({}));
                                if (!resp.ok) {
                                    throw new Error((data && data.error) || "Failed to reject user.");
                                }
                                loadUsers();
                            } catch (err) {
                                console.error(err);
                                alert(err.message || "Failed to reject user.");
                            }
                        });

                        actionsCell.appendChild(approveBtn);
                        actionsCell.appendChild(rejectBtn);
                    } else {
                        actionsCell.textContent = "";
                    }

                    tr.appendChild(nameCell);
                    tr.appendChild(roleCell);
                    tr.appendChild(statusCell);
                    tr.appendChild(createdCell);
                    tr.appendChild(actionsCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error(err);
                tbody.innerHTML = '<tr><td colspan="5" class="px-3 py-6 text-center text-xs text-rose-400">Failed to load users.</td></tr>';
            }
        }

        // Infra status polling
        let infraPollInterval = null;

        async function pollInfraStatus(projectName) {
            const lastStatus = document.getElementById("infra-last-status");
            if (!projectName) return;
            try {
                const resp = await fetch("/v1/infra/status?project=" + encodeURIComponent(projectName), {
                    method: "GET",
                    headers: authHeaders({ "Accept": "application/json" }),
                });
                const data = await resp.json().catch(() => ({}));
                if (!resp.ok) {
                    const msg = data && data.error ? data.error : "Failed to fetch status.";
                    throw new Error(msg);
                }
                const state = data.state || "Unknown";
                const color = data.color || "grey";
                if (lastStatus) {
                    lastStatus.textContent = "Current status for " + projectName + ": " + state + " (" + color + ")";
                }
            } catch (err) {
                console.error(err);
                if (lastStatus) {
                    lastStatus.textContent = "Status error: " + (err.message || "Unknown error");
                }
            }
        }

        function startInfraPolling(projectName) {
            if (infraPollInterval) {
                clearInterval(infraPollInterval);
                infraPollInterval = null;
            }
            if (!projectName) {
                return;
            }
            // Poll immediately, then every 5 seconds.
            pollInfraStatus(projectName);
            infraPollInterval = setInterval(function () {
                pollInfraStatus(projectName);
            }, 5000);
        }

        // Wire up event listeners once the DOM is ready
        document.addEventListener("DOMContentLoaded", function () {
            // Sidebar view switching
            document.getElementById("nav-assets").addEventListener("click", function () {
                setActiveView("assets");
            });
            document.getElementById("nav-catalog").addEventListener("click", function () {
                setActiveView("catalog");
            });
            document.getElementById("nav-infra").addEventListener("click", function () {
                setActiveView("infra");
            });
            const navUsersBtn = document.getElementById("nav-users");
            if (navUsersBtn) {
                navUsersBtn.addEventListener("click", function () {
                    setActiveView("users");
                });
            }

            // Default view
            setActiveView("assets");

            // Scanner actions
            document.getElementById("scan-button").addEventListener("click", function () {
                runScan();
            });
            document.getElementById("domains-input").addEventListener("keydown", function (event) {
                if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                    event.preventDefault();
                    runScan();
                }
            });

            // Create Service modal events
            const openBtn = document.getElementById("open-create-service");
            if (openBtn) {
                openBtn.addEventListener("click", function () {
                    openCreateServiceModal();
                });
            }
            const closeBtn = document.getElementById("create-service-close");
            if (closeBtn) {
                closeBtn.addEventListener("click", function () {
                    closeCreateServiceModal();
                });
            }
            const cancelBtn = document.getElementById("svc-cancel");
            if (cancelBtn) {
                cancelBtn.addEventListener("click", function (e) {
                    e.preventDefault();
                    closeCreateServiceModal();
                });
            }

            const svcForm = document.getElementById("create-service-form");
            if (svcForm) {
                svcForm.addEventListener("submit", submitCreateService);
            }

            // Add User modal events
            const openAddUserBtn = document.getElementById("open-add-user");
            if (openAddUserBtn) {
                openAddUserBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-user-modal");
                    if (modal) {
                        modal.classList.remove("hidden");
                        modal.classList.add("flex");
                    }
                });
            }
            const closeAddUserBtn = document.getElementById("add-user-close");
            if (closeAddUserBtn) {
                closeAddUserBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-user-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-user-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-user-form");
                    if (form) form.reset();
                });
            }
            const cancelAddUserBtn = document.getElementById("add-user-cancel");
            if (cancelAddUserBtn) {
                cancelAddUserBtn.addEventListener("click", function (e) {
                    e.preventDefault();
                    const modal = document.getElementById("add-user-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-user-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-user-form");
                    if (form) form.reset();
                });
            }
            const addUserForm = document.getElementById("add-user-form");
            if (addUserForm) {
                addUserForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const username = (document.getElementById("add-username").value || "").trim();
                    const password = (document.getElementById("add-password").value || "").trim();
                    const role = (document.getElementById("add-role").value || "user").trim();
                    const errorEl = document.getElementById("add-user-error");
                    const submitBtn = document.getElementById("add-user-submit");

                    errorEl.textContent = "";
                    if (!username || !password) {
                        errorEl.textContent = "Username and password are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    try {
                        const resp = await apiFetch("/v1/admin/users", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                                "Accept": "application/json",
                            },
                            body: JSON.stringify({ username, password, role }),
                        });
                        const data = await resp.json().catch(() => ({}));
                        if (!resp.ok) {
                            const msg = data && data.error ? data.error : "Failed to create user.";
                            throw new Error(msg);
                        }
                        // Close modal and refresh user list
                        const modal = document.getElementById("add-user-modal");
                        if (modal) {
                            modal.classList.add("hidden");
                            modal.classList.remove("flex");
                        }
                        const form = document.getElementById("add-user-form");
                        if (form) form.reset();
                        loadUsers();
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while creating user.";
                    } finally {
                        submitBtn.disabled = false;
                    }
                });
            }

            // Infra actions
            const infraBtn = document.getElementById("infra-submit");
            if (infraBtn) {
                infraBtn.addEventListener("click", submitInfraProvision);
            }

            const refreshProjectsBtn = document.getElementById("refresh-projects");
            if (refreshProjectsBtn) {
                refreshProjectsBtn.addEventListener("click", loadProjects);
            }

            const refreshInfraBtn = document.getElementById("refresh-infra");
            if (refreshInfraBtn) {
                refreshInfraBtn.addEventListener("click", loadInfraResources);
            }

            const refreshInfraStatusBtn = document.getElementById("refresh-infra-status");
            if (refreshInfraStatusBtn) {
                refreshInfraStatusBtn.addEventListener("click", function () {
                    const name = (document.getElementById("infra-name").value || "").trim();
                    if (name) {
                        startInfraPolling(name);
                    }
                });
            }

            const logoutBtn = document.getElementById("logout-button");
            if (logoutBtn) {
                logoutBtn.addEventListener("click", function () {
                    clearAuth();
                    updateUserUI();
                    ensureAuthenticated();
                });
            }

            const loginForm = document.getElementById("login-form");
            if (loginForm) {
                loginForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const username = (document.getElementById("login-username").value || "").trim();
                    const password = (document.getElementById("login-password").value || "").trim();
                    const errorEl = document.getElementById("login-error");
                    const submitBtn = document.getElementById("login-submit");

                    errorEl.textContent = "";
                    if (!username || !password) {
                        errorEl.textContent = "Username and password are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    try {
                        // Login flow only (public registration is disabled)
                        const resp = await fetch("/v1/auth/login", {
                            method: "POST",
                            headers: {
                                "Content-Type": "application/json",
                                "Accept": "application/json",
                            },
                            body: JSON.stringify({ username, password }),
                        });
                        const data = await resp.json().catch(() => ({}));
                        if (!resp.ok) {
                            const msg = data && data.error ? data.error : "Login failed.";
                            throw new Error(msg);
                        }
                        saveAuth(data.token, { username: data.username, role: data.role });
                        updateUserUI();
                        ensureAuthenticated();
                        // Load initial data after login
                        loadProjects();
                        loadInfraOptions();
                        loadInfraResources();
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while logging in.";
                    } finally {
                        submitBtn.disabled = false;
                    }
                });
            }

            // Catalog "View API" buttons
            const apiButtons = document.querySelectorAll(".view-api-btn");
            apiButtons.forEach(function (btn) {
                btn.addEventListener("click", function () {
                    const svcUrl = btn.getAttribute("data-service-url");
                    if (!svcUrl) {
                        console.warn("Missing service URL on View API button");
                        return;
                    }
                    openSwaggerForService(svcUrl);
                });
            });

            const swaggerClose = document.getElementById("swagger-close");
            if (swaggerClose) {
                swaggerClose.addEventListener("click", function () {
                    closeSwaggerModal();
                });
            }

            // Initial auth state
            updateUserUI();
            ensureAuthenticated();

            // Initial data loads if already authenticated
            if (getToken()) {
                loadProjects();
                loadInfraOptions();
                loadInfraResources();
            }
        });

        // Swagger UI integration
        let swaggerUIInstance = null;

        function openSwaggerForService(serviceUrl) {
            const modal = document.getElementById("swagger-modal");
            const label = document.getElementById("swagger-service-label");

            if (!modal) return;

            const encodedId = encodeURIComponent(serviceUrl);
            const docsUrl = "/v1/catalog/" + encodedId + "/docs";

            label.textContent = "Service: " + serviceUrl;
            modal.classList.remove("hidden");
            modal.classList.add("flex");

            // Initialize or re-initialize Swagger UI
            if (window.SwaggerUIBundle) {
                swaggerUIInstance = window.SwaggerUIBundle({
                    url: docsUrl,
                    dom_id: "#swagger-ui",
                    presets: [window.SwaggerUIBundle.presets.apis],
                    layout: "BaseLayout",
                    requestInterceptor: function (req) {
                        const token = getToken();
                        if (token) {
                            req.headers["Authorization"] = "Bearer " + token;
                        }
                        return req;
                    },
                });
            } else {
                console.error("SwaggerUIBundle is not available from CDN.");
            }
        }

        function closeSwaggerModal() {
            const modal = document.getElementById("swagger-modal");
            if (modal) {
                modal.classList.add("hidden");
                modal.classList.remove("flex");
            }
        }
    </script>
</body>
</html>`

	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(html))
}

// handleCreateProject handles POST /v1/projects to scaffold a new service repository.
func handleCreateProject(c *gin.Context) {
	type requestBody struct {
		ProjectName string `json:"project_name"`
		Description string `json:"description"`
		GitHubToken string `json:"github_token"`
	}

	var body requestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if body.ProjectName == "" || body.GitHubToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "project_name and github_token are required",
		})
		return
	}

	cfg := scaffolder.ServiceConfig{
		ProjectName: body.ProjectName,
		Description: body.Description,
		GitHubToken: body.GitHubToken,
	}

	repoURL, err := scaffolder.CreateService(c.Request.Context(), cfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "failed to create project",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"project_name": body.ProjectName,
		"repository":   repoURL,
	})
}

// handleCreateUser creates a new user. This is an admin-only endpoint.
// Users created by admins are automatically set to "active" status.
func handleCreateUser(c *gin.Context) {
	type requestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	var body requestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if body.Username == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username and password are required",
		})
		return
	}

	role := body.Role
	if role == "" {
		role = "user"
	}

	hashed, err := auth.HashPassword(body.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to hash password",
		})
		return
	}

	user := database.User{
		Username: body.Username,
		Password: hashed,
		Role:     role,
		Status:   "active", // Admin-created users are automatically active
	}

	if err := database.DB.Create(&user).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, gin.H{
				"error": "username already exists",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to create user",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role,
		"status":   user.Status,
	})
}

// handleLogin authenticates a user and returns a JWT token.
func handleLogin(c *gin.Context) {
	type requestBody struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	var body requestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if body.Username == "" || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "username and password are required",
		})
		return
	}

	var user database.User
	if err := database.DB.Where("username = ?", body.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid username or password",
		})
		return
	}

	if !auth.CheckPassword(user.Password, body.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid username or password",
		})
		return
	}

	// Enforce account status.
	switch strings.ToLower(user.Status) {
	case "pending":
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Account pending approval",
		})
		return
	case "disabled":
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Account disabled",
		})
		return
	}

	token, err := auth.GenerateToken(user.ID, user.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to generate token",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"username": user.Username,
		"role":     user.Role,
	})
}

// handleCatalogDocs proxies stored API documentation for a service.
// The serviceId path parameter is expected to be a URL-encoded base URL of the service.
// Example: /v1/catalog/https:%2F%2Fapi.example.com/docs -> https://api.example.com
func handleCatalogDocs(c *gin.Context) {
	serviceID := c.Param("serviceId")
	if serviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "serviceId is required",
		})
		return
	}

	serviceURL, err := url.PathUnescape(serviceID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid serviceId encoding",
		})
		return
	}

	doc, err := catalog.FetchServiceDocs(serviceURL)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{
			"error":   "failed to fetch service documentation",
			"details": err.Error(),
		})
		return
	}

	// Return the raw OpenAPI/Swagger specification, which is compatible with Swagger UI.
	c.JSON(http.StatusOK, doc.Spec)
}

// handleInfraOptions returns the predefined infrastructure size options.
func handleInfraOptions(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"sizes": infra.DatabaseSizeOptions,
	})
}

// handleInfraProvision logs the intent to provision a new database with the selected size.
// This is a placeholder that will be wired to Crossplane in a future iteration.
func handleInfraProvision(c *gin.Context) {
	var req infra.DatabaseResource
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid request body",
		})
		return
	}

	if req.Name == "" || req.Engine == "" || req.Size == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "name, engine, and size are required",
		})
		return
	}

	sizeOpt, ok := infra.FindSizeOption(req.Size)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "unknown size; valid values are Small, Medium, Large",
		})
		return
	}

	// Log the intent to provision. This is where Crossplane integration will happen later.
	log.Printf(
		"Provision request: name=%s engine=%s size=%s (vCPU=%d, RAM=%dGB)",
		req.Name,
		req.Engine,
		sizeOpt.Name,
		sizeOpt.VCPU,
		sizeOpt.RAMGB,
	)

	// For now, mark the resource as Requested.
	req.Status = "Requested"

	// Persist the infrastructure request.
	infra.RecordInfrastructureRequest(req.Name, req.Engine, req.Size)

	c.JSON(http.StatusAccepted, gin.H{
		"message":                "provision request accepted",
		"resource":               req,
		"resolved_size_vcpu":     sizeOpt.VCPU,
		"resolved_size_ram_gb":   sizeOpt.RAMGB,
		"tracked_project_name":   req.Name,
		"tracked_project_engine": req.Engine,
		"tracked_project_size":   req.Size,
	})
}

// handleInfraStatus exposes a simplified view of the Crossplane managed resource status.
func handleInfraStatus(c *gin.Context) {
	projectName := c.Query("project")
	if projectName == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "project query parameter is required",
		})
		return
	}

	status, err := infra.GetResourceStatus(projectName)
	if err != nil {
		// Even if there is an error, prefer returning a best-effort status.
		log.Printf("GetResourceStatus error for project %s: %v", projectName, err)
	}

	c.JSON(http.StatusOK, gin.H{
		"project": projectName,
		"state":   status.State,
		"color":   status.Color,
	})
}

// handleListProjects returns all projects from the database ordered by creation time.
func handleListProjects(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database not initialized",
		})
		return
	}

	var projects []database.Project
	if err := database.DB.Order("created_at desc").Find(&projects).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to list projects",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"projects": projects,
	})
}

// handleInfraList returns all infrastructure resources from the database.
func handleInfraList(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database not initialized",
		})
		return
	}

	var resources []database.InfrastructureResource
	if err := database.DB.Order("created_at desc").Find(&resources).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to list infrastructure resources",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"resources": resources,
	})
}

// handleListPendingUsers returns only users with pending status.
func handleListPendingUsers(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database not initialized",
		})
		return
	}

	var users []database.User
	if err := database.DB.Where("status = ?", "pending").Order("created_at desc").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to list pending users",
		})
		return
	}

	// Do not expose password hashes.
	for i := range users {
		users[i].Password = ""
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// handleListAllUsers returns all users. This route should be protected by admin-only middleware.
func handleListAllUsers(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database not initialized",
		})
		return
	}

	var users []database.User
	if err := database.DB.Order("created_at desc").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to list users",
		})
		return
	}

	// Do not expose password hashes.
	for i := range users {
		users[i].Password = ""
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

// handleApproveUser sets the user status to active.
func handleApproveUser(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user ID is required"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	if err := database.DB.Model(&user).Update("status", "active").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":     user.ID,
		"status": "active",
	})
}

// handleRejectUser disables or removes a user account.
func handleRejectUser(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user ID is required"})
		return
	}

	var user database.User
	if err := database.DB.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	// Mark the account as disabled instead of deleting it.
	if err := database.DB.Model(&user).Update("status", "disabled").Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user status"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":     user.ID,
		"status": "disabled",
	})
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
