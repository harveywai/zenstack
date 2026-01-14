package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"github.com/harveywai/zenstack/pkg/auth"
	"github.com/harveywai/zenstack/pkg/catalog"
	"github.com/harveywai/zenstack/pkg/database"
	"github.com/harveywai/zenstack/pkg/infra"
	"github.com/harveywai/zenstack/pkg/middleware"
	"github.com/harveywai/zenstack/pkg/notify"
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

// SSLScanResult represents the result of a deep SSL certificate scan
type SSLScanResult struct {
	DomainName    string
	ExpiryDate    time.Time
	DaysRemaining int
	IsReachable   bool
}

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
		v1.GET("/domains", handleListDomains)
		v1.PUT("/domains/:id/auto-renew", handleUpdateAutoRenew)
		v1.POST("/domains/:id/renew", handleManualRenew)
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
		v1Admin.GET("/dashboard/stats", handleDashboardStats)

		// Notification configuration endpoints
		v1Admin.GET("/notifications/configs", handleListNotificationConfigs)
		v1Admin.POST("/notifications/configs", handleCreateNotificationConfig)
		v1Admin.PUT("/notifications/configs/:id", handleUpdateNotificationConfig)
		v1Admin.DELETE("/notifications/configs/:id", handleDeleteNotificationConfig)

		// Message template endpoints
		v1Admin.GET("/notifications/templates", handleListMessageTemplates)
		v1Admin.POST("/notifications/templates", handleCreateMessageTemplate)
		v1Admin.PUT("/notifications/templates/:id", handleUpdateMessageTemplate)
		v1Admin.DELETE("/notifications/templates/:id", handleDeleteMessageTemplate)

		// Telegram notification config endpoints
		v1Admin.GET("/notifications/telegram", handleListTelegramConfigs)
		v1Admin.POST("/notifications/telegram", handleCreateTelegramConfig)
		v1Admin.PUT("/notifications/telegram/:id", handleUpdateTelegramConfig)
		v1Admin.DELETE("/notifications/telegram/:id", handleDeleteTelegramConfig)
		v1Admin.POST("/notifications/telegram/:id/test", handleTestTelegramConnection)

		// Settings endpoints (simplified API for Telegram configuration)
		v1Admin.POST("/settings/telegram", handleSaveTelegramSettings)
	}

	// Dashboard stats endpoint (Admin only) - legacy endpoint for backward compatibility
	v1Dashboard := r.Group("/v1/dashboard")
	v1Dashboard.Use(middleware.AuthMiddleware(), middleware.RoleMiddleware("admin"))
	{
		v1Dashboard.GET("/stats", handleDashboardStats)
	}

	// Start background SSL monitoring task (new version with deep scan)
	go startSSLScanner()

	// Start background HTTP health monitoring worker (new version)
	go startLiveMonitor()

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
    <style>
        @keyframes pulse-red {
            0%, 100% {
                background-color: rgba(239, 68, 68, 0.1);
                border-left-color: rgb(239, 68, 68);
            }
            50% {
                background-color: rgba(239, 68, 68, 0.2);
                border-left-color: rgb(220, 38, 38);
            }
        }
        .pulse-critical {
            animation: pulse-red 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
        }
        @keyframes breathe-green {
            0%, 100% {
                opacity: 1;
                box-shadow: 0 0 8px rgba(34, 197, 94, 0.6);
            }
            50% {
                opacity: 0.6;
                box-shadow: 0 0 16px rgba(34, 197, 94, 0.9);
            }
        }
        @keyframes breathe-red {
            0%, 100% {
                opacity: 1;
                box-shadow: 0 0 8px rgba(239, 68, 68, 0.6);
            }
            50% {
                opacity: 0.6;
                box-shadow: 0 0 16px rgba(239, 68, 68, 0.9);
            }
        }
        @keyframes blink-red {
            0%, 100% {
                opacity: 1;
                box-shadow: 0 0 8px rgba(239, 68, 68, 0.8);
            }
            50% {
                opacity: 0.3;
                box-shadow: 0 0 20px rgba(239, 68, 68, 1);
            }
        }
        @keyframes breathe-yellow {
            0%, 100% {
                opacity: 1;
                box-shadow: 0 0 8px rgba(234, 179, 8, 0.6);
            }
            50% {
                opacity: 0.6;
                box-shadow: 0 0 16px rgba(234, 179, 8, 0.9);
            }
        }
        .live-indicator {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-right: 6px;
            vertical-align: middle;
        }
        .live-indicator.live {
            background-color: rgb(34, 197, 94);
            animation: breathe-green 2s ease-in-out infinite;
        }
        .live-indicator.down {
            background-color: rgb(239, 68, 68);
            animation: blink-red 1s ease-in-out infinite;
        }
        .live-indicator.warning {
            background-color: rgb(234, 179, 8);
            animation: breathe-yellow 2s ease-in-out infinite;
        }
    </style>
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
                    id="nav-dashboard"
                    data-view="dashboard"
                    class="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-800 text-slate-50 font-medium"
                >
                    <span class="h-2 w-2 rounded-full bg-purple-400"></span>
                    Dashboard
                </button>
                <button
                    id="nav-assets"
                    data-view="assets"
                    class="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-300 hover:bg-slate-800/60"
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
                <button
                    id="nav-notifications"
                    data-view="notifications"
                    class="hidden w-full flex items-center gap-2 px-3 py-2 rounded-lg text-slate-300 hover:bg-slate-800/60"
                >
                    <span class="h-2 w-2 rounded-full bg-indigo-400"></span>
                    Notifications
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
                    <!-- Dashboard View -->
                    <section id="view-dashboard" class="space-y-6">
                        <!-- Statistic Cards -->
                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
                            <div class="bg-gradient-to-br from-emerald-500/20 to-emerald-600/10 border border-emerald-500/30 rounded-2xl p-6 shadow-xl shadow-emerald-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-emerald-300/80 font-medium mb-1">Total Assets</p>
                                        <p id="stat-total-domains" class="text-3xl font-bold text-emerald-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-emerald-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gradient-to-br from-red-500/20 to-red-600/10 border border-red-500/30 rounded-2xl p-6 shadow-xl shadow-red-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-red-300/80 font-medium mb-1">SSL Critical</p>
                                        <p id="stat-ssl-critical" class="text-3xl font-bold text-red-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-red-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gradient-to-br from-amber-500/20 to-amber-600/10 border border-amber-500/30 rounded-2xl p-6 shadow-xl shadow-amber-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-amber-300/80 font-medium mb-1">SSL Warning</p>
                                        <p id="stat-ssl-warning" class="text-3xl font-bold text-amber-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-amber-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gradient-to-br from-sky-500/20 to-sky-600/10 border border-sky-500/30 rounded-2xl p-6 shadow-xl shadow-sky-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-sky-300/80 font-medium mb-1">Projects</p>
                                        <p id="stat-project-count" class="text-3xl font-bold text-sky-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-sky-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gradient-to-br from-purple-500/20 to-purple-600/10 border border-purple-500/30 rounded-2xl p-6 shadow-xl shadow-purple-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-purple-300/80 font-medium mb-1">Global Availability</p>
                                        <p id="stat-global-availability" class="text-3xl font-bold text-purple-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-purple-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            <div class="bg-gradient-to-br from-red-500/20 to-red-600/10 border border-red-500/30 rounded-2xl p-6 shadow-xl shadow-red-500/10">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-xs text-red-300/80 font-medium mb-1">Sites Down</p>
                                        <p id="stat-sites-down" class="text-3xl font-bold text-red-400">-</p>
                                    </div>
                                    <div class="h-12 w-12 rounded-xl bg-red-500/20 flex items-center justify-center">
                                        <svg class="h-6 w-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- Charts Section -->
                        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            <!-- Doughnut Chart: Domain Suffix Distribution -->
                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div>
                                    <h3 class="text-sm font-semibold tracking-tight">Domain Suffix Distribution</h3>
                                    <p class="text-xs text-slate-400 mt-1">Distribution of domains by TLD suffix (e.g., .com, .io, .jp)</p>
                                </div>
                                <div class="h-64 flex items-center justify-center">
                                    <canvas id="project-types-chart"></canvas>
                                </div>
                            </section>

                            <!-- Bar Chart: Domains Expiry by Month -->
                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div>
                                    <h3 class="text-sm font-semibold tracking-tight">Domains Expiry by Month</h3>
                                    <p class="text-xs text-slate-400 mt-1">Number of domains with SSL certificates expiring each month (next 12 months)</p>
                                </div>
                                <div class="h-64 flex items-center justify-center">
                                    <canvas id="domain-status-chart"></canvas>
                                </div>
                            </section>
                        </div>
                    </section>

                    <!-- Assets View: Domain & SSL Scanner -->
                    <section id="view-assets" class="space-y-6 hidden">
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

                        <!-- Monitored Domains List -->
                        <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                            <div class="flex items-center justify-between gap-3 flex-wrap">
                                <div>
                                    <h3 class="text-sm font-semibold tracking-tight">Monitored Domains</h3>
                                    <p class="text-xs text-slate-400">
                                        Domains saved in database with SSL monitoring. Auto-scanned every 6 hours.
                                    </p>
                                </div>
                                <button
                                    id="refresh-domains"
                                    class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-200 hover:bg-slate-800/80"
                                >
                                    Refresh
                                </button>
                            </div>
                            <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                <table class="min-w-full divide-y divide-slate-800 text-sm">
                                    <thead class="bg-slate-900/80">
                                        <tr>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Domain</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Live Status</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">SSL Status</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">SSL Expiry</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Days Remaining</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Last Check</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Auto-Renew</th>
                                            <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="domains-body" class="divide-y divide-slate-900/80">
                                        <tr>
                                            <td colspan="8" class="px-3 py-6 text-center text-xs text-slate-500">
                                                Loading domains...
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

                        <!-- Notifications View: Admin only -->
                        <section id="view-notifications" class="space-y-6 hidden">
                            <!-- Telegram Configuration Section -->
                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div class="flex items-center justify-between gap-3 flex-wrap">
                                    <div>
                                        <h2 class="text-base font-semibold tracking-tight">Telegram Bot Configuration</h2>
                                        <p class="text-xs text-slate-400 mt-1">
                                            Configure Telegram bot token and chat ID for notifications
                                        </p>
                                    </div>
                                </div>
                                
                                <!-- Telegram Config Form -->
                                <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-4">
                                    <form id="telegram-config-form" class="space-y-3">
                                        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
                                            <div>
                                                <label class="block text-xs font-medium text-slate-300 mb-1" for="tg-bot-token">
                                                    Bot Token
                                                </label>
                                                <input
                                                    id="tg-bot-token"
                                                    type="text"
                                                    class="w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                                    placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
                                                />
                                            </div>
                                            <div>
                                                <label class="block text-xs font-medium text-slate-300 mb-1" for="tg-chat-id">
                                                    Chat ID
                                                </label>
                                                <input
                                                    id="tg-chat-id"
                                                    type="text"
                                                    class="w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                                    placeholder="-1001234567890"
                                                />
                                            </div>
                                        </div>
                                        <div class="flex items-center justify-between">
                                            <label class="flex items-center gap-2 text-xs font-medium text-slate-300">
                                                <input
                                                    id="tg-is-active"
                                                    type="checkbox"
                                                    class="rounded border-slate-700 bg-slate-950/60 text-emerald-500 focus:ring-2 focus:ring-emerald-500/70"
                                                    checked
                                                />
                                                Active
                                            </label>
                                            <div class="flex items-center gap-2">
                                                <button
                                                    type="button"
                                                    id="test-telegram-btn"
                                                    class="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-sky-300 hover:bg-sky-500/10"
                                                >
                                                    Test TG Notification
                                                </button>
                                                <button
                                                    type="submit"
                                                    id="save-telegram-config-btn"
                                                    class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                                                >
                                                    Save Config
                                                </button>
                                            </div>
                                        </div>
                                        <p id="telegram-config-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                                        <p id="telegram-config-success" class="text-[11px] text-emerald-400 min-h-[1.25rem]"></p>
                                    </form>
                                </div>

                                <!-- Existing Telegram Configs List -->
                                <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                    <table class="min-w-full divide-y divide-slate-800 text-sm">
                                        <thead class="bg-slate-900/80">
                                            <tr>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Chat ID</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="telegram-configs-body" class="divide-y divide-slate-900/80">
                                            <tr>
                                                <td colspan="3" class="px-3 py-6 text-center text-xs text-slate-500">
                                                    Loading Telegram configs...
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </section>

                            <!-- Message Templates Section -->
                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div class="flex items-center justify-between gap-3 flex-wrap">
                                    <div>
                                        <h2 class="text-base font-semibold tracking-tight">Message Templates</h2>
                                        <p class="text-xs text-slate-400 mt-1">
                                            Edit notification message templates for Site Down and SSL Expiring events
                                        </p>
                                    </div>
                                </div>
                                <div id="template-editor-container" class="space-y-4">
                                    <!-- Site Down Template Editor -->
                                    <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-3">
                                        <div class="flex items-center justify-between">
                                            <h3 class="text-sm font-semibold text-slate-200">Site Down Template</h3>
                                            <button
                                                id="save-sitedown-template"
                                                class="inline-flex items-center gap-1 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 hover:bg-emerald-400"
                                            >
                                                Save
                                            </button>
                                        </div>
                                        <textarea
                                            id="sitedown-template-text"
                                            rows="3"
                                            class="w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                            placeholder="🚨 告警：站点 {{domain}} 无法访问！状态码：{{status}}"
                                        ></textarea>
                                        <p class="text-[11px] text-slate-500">
                                            Available variables: {{domain}}, {{status}}, {{status_code}}, {{code}}
                                        </p>
                                    </div>
                                    
                                    <!-- SSL Expiring Template Editor -->
                                    <div class="bg-slate-950/60 border border-slate-800 rounded-xl p-4 space-y-3">
                                        <div class="flex items-center justify-between">
                                            <h3 class="text-sm font-semibold text-slate-200">SSL Expiring Template</h3>
                                            <button
                                                id="save-sslexpired-template"
                                                class="inline-flex items-center gap-1 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 hover:bg-emerald-400"
                                            >
                                                Save
                                            </button>
                                        </div>
                                        <textarea
                                            id="sslexpired-template-text"
                                            rows="3"
                                            class="w-full rounded-lg border border-slate-800 bg-slate-900/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                                            placeholder="🔒 证书预警：域名 {{domain}} 的 SSL 证书将在 {{days}} 天后过期。"
                                        ></textarea>
                                        <p class="text-[11px] text-slate-500">
                                            Available variables: {{domain}}, {{days}}, {{days_remaining}}, {{expiry}}
                                        </p>
                                    </div>
                                </div>
                            </section>

                            <!-- Webhook Configurations Section (kept for backward compatibility) -->
                            <section class="bg-slate-900/60 border border-slate-800 rounded-2xl shadow-xl shadow-slate-950/40 p-6 space-y-4">
                                <div class="flex items-center justify-between gap-3 flex-wrap">
                                    <div>
                                        <h2 class="text-base font-semibold tracking-tight">Webhook Configurations</h2>
                                        <p class="text-xs text-slate-400 mt-1">
                                            Configure webhook URLs for notification platforms (DingTalk, Feishu, Slack, etc.)
                                        </p>
                                    </div>
                                    <button
                                        id="open-add-notification-config"
                                        class="inline-flex items-center gap-2 rounded-xl bg-emerald-500 px-4 py-2 text-xs font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 transition hidden"
                                    >
                                        <span class="text-sm">Add Config</span>
                                    </button>
                                </div>
                                <div class="overflow-hidden rounded-xl border border-slate-800 bg-slate-950/60">
                                    <table class="min-w-full divide-y divide-slate-800 text-sm">
                                        <thead class="bg-slate-900/80">
                                            <tr>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Platform</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Webhook URL</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Status</th>
                                                <th class="px-3 py-2 text-left text-xs font-semibold text-slate-400">Actions</th>
                                            </tr>
                                        </thead>
                                        <tbody id="notification-configs-body" class="divide-y divide-slate-900/80">
                                            <tr>
                                                <td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">
                                                    Loading notification configs...
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </section>
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

    <!-- Add Notification Config Modal -->
    <div
        id="add-notification-config-modal"
        class="fixed inset-0 hidden z-40 items-center justify-center bg-slate-950/70 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 p-6 space-y-4">
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Add Notification Config</h2>
                    <p class="text-[11px] text-slate-400">
                        Configure a webhook URL for notification platforms (DingTalk, Feishu, Slack, etc.)
                    </p>
                </div>
                <button
                    id="add-notification-config-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close modal"
                >
                    ✕
                </button>
            </div>
            <form id="add-notification-config-form" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="config-platform">
                        Platform
                    </label>
                    <select
                        id="config-platform"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        required
                    >
                        <option value="">Select Platform</option>
                        <option value="DingTalk">DingTalk</option>
                        <option value="Feishu">Feishu</option>
                        <option value="Slack">Slack</option>
                        <option value="Webhook">Generic Webhook</option>
                    </select>
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="config-webhook-url">
                        Webhook URL
                    </label>
                    <input
                        id="config-webhook-url"
                        type="url"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="https://..."
                        required
                    />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="config-secret-key">
                        Secret Key (Optional)
                    </label>
                    <input
                        id="config-secret-key"
                        type="password"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="••••••••"
                    />
                </div>
                <div>
                    <label class="flex items-center gap-2 text-xs font-medium text-slate-300">
                        <input
                            id="config-is-active"
                            type="checkbox"
                            class="rounded border-slate-700 bg-slate-950/60 text-emerald-500 focus:ring-2 focus:ring-emerald-500/70"
                            checked
                        />
                        Active
                    </label>
                </div>
                <p id="add-notification-config-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                <div class="flex items-center justify-end gap-2">
                    <button
                        type="button"
                        id="add-notification-config-cancel"
                        class="rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800/80"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        id="add-notification-config-submit"
                        class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                        <span>Add Config</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Add Telegram Config Modal -->
    <div
        id="add-telegram-config-modal"
        class="fixed inset-0 hidden z-40 items-center justify-center bg-slate-950/70 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 p-6 space-y-4">
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Add Telegram Config</h2>
                    <p class="text-[11px] text-slate-400">
                        Configure Telegram bot token and chat ID for notifications
                    </p>
                </div>
                <button
                    id="add-telegram-config-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close modal"
                >
                    ✕
                </button>
            </div>
            <form id="add-telegram-config-form" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="telegram-token">
                        Bot Token
                    </label>
                    <input
                        id="telegram-token"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
                        required
                    />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="telegram-chat-id">
                        Chat ID
                    </label>
                    <input
                        id="telegram-chat-id"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="-1001234567890"
                        required
                    />
                </div>
                <div>
                    <label class="flex items-center gap-2 text-xs font-medium text-slate-300">
                        <input
                            id="telegram-is-active"
                            type="checkbox"
                            class="rounded border-slate-700 bg-slate-950/60 text-emerald-500 focus:ring-2 focus:ring-emerald-500/70"
                            checked
                        />
                        Active
                    </label>
                </div>
                <p id="add-telegram-config-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                <div class="flex items-center justify-end gap-2">
                    <button
                        type="button"
                        id="add-telegram-config-cancel"
                        class="rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800/80"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        id="add-telegram-config-submit"
                        class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                        <span>Add Config</span>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Add Message Template Modal -->
    <div
        id="add-template-modal"
        class="fixed inset-0 hidden z-40 items-center justify-center bg-slate-950/70 backdrop-blur-sm"
        aria-hidden="true"
    >
        <div class="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900 shadow-xl shadow-black/50 p-6 space-y-4">
            <div class="flex items-center justify-between mb-3">
                <div>
                    <h2 class="text-sm font-semibold tracking-tight">Add Message Template</h2>
                    <p class="text-[11px] text-slate-400">
                        Create a notification template for specific events (SSL_EXPIRED, SITE_DOWN, etc.)
                    </p>
                </div>
                <button
                    id="add-template-close"
                    class="text-slate-400 hover:text-slate-100 text-xs"
                    aria-label="Close modal"
                >
                    ✕
                </button>
            </div>
            <form id="add-template-form" class="space-y-3">
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="template-event-name">
                        Event Name
                    </label>
                    <input
                        id="template-event-name"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="SSL_EXPIRED"
                        required
                    />
                    <p class="text-[11px] text-slate-500 mt-1">
                        Examples: SSL_EXPIRED, SITE_DOWN, DOMAIN_EXPIRING
                    </p>
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="template-title">
                        Title Template
                    </label>
                    <input
                        id="template-title"
                        type="text"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="SSL Certificate Expired: {{domain}}"
                        required
                    />
                </div>
                <div>
                    <label class="block text-xs font-medium text-slate-300" for="template-body">
                        Body Template
                    </label>
                    <textarea
                        id="template-body"
                        rows="4"
                        class="mt-1 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 focus:border-emerald-500/70"
                        placeholder="The SSL certificate for {{domain}} expired on {{expiry_date}}"
                        required
                    ></textarea>
                </div>
                <p id="add-template-error" class="text-[11px] text-rose-400 min-h-[1.25rem]"></p>
                <div class="flex items-center justify-end gap-2">
                    <button
                        type="button"
                        id="add-template-cancel"
                        class="rounded-lg border border-slate-700 px-3 py-1.5 text-[11px] text-slate-300 hover:bg-slate-800/80"
                    >
                        Cancel
                    </button>
                    <button
                        type="submit"
                        id="add-template-submit"
                        class="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-3 py-1.5 text-[11px] font-medium text-slate-950 shadow-lg shadow-emerald-500/25 hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-500/70 disabled:opacity-60 disabled:cursor-not-allowed"
                    >
                        <span>Add Template</span>
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
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        // Global error handler to prevent JS errors from blocking login
        window.onerror = function(msg) {
            console.log("Caught Error: " + msg);
            return true;
        };

        // Authentication helpers
        function getToken() {
            try {
                return localStorage.getItem("token") || "";
            } catch (_) {
                return "";
            }
        }

        function getCurrentUser() {
            try {
                const raw = localStorage.getItem("user");
                if (!raw) return null;
                return JSON.parse(raw);
            } catch (_) {
                return null;
            }
        }

        function saveAuth(token, user) {
            try {
                localStorage.setItem("token", token || "");
                localStorage.setItem("user", JSON.stringify(user || {}));
            } catch (_) {}
        }

        function clearAuth() {
            try {
                localStorage.removeItem("token");
                localStorage.removeItem("user");
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
            const navNotifications = document.getElementById("nav-notifications");
            const addUserBtn = document.getElementById("open-add-user");
            const addNotificationConfigBtn = document.getElementById("open-add-notification-config");
            const addTemplateBtn = document.getElementById("open-add-template");
            const addTelegramConfigBtn = document.getElementById("open-add-telegram-config");

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
                const userData = localStorage.getItem("user");
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
            if (navNotifications) {
                if (isAdmin) {
                    navNotifications.classList.remove("hidden");
                    navNotifications.style.display = "";
                } else {
                    navNotifications.classList.add("hidden");
                    navNotifications.style.display = "none";
                }
            }
            if (addUserBtn) {
                if (role === "admin") {
                    addUserBtn.classList.remove("hidden");
                } else {
                    addUserBtn.classList.add("hidden");
                }
            }
            if (addNotificationConfigBtn) {
                if (role === "admin") {
                    addNotificationConfigBtn.classList.remove("hidden");
                } else {
                    addNotificationConfigBtn.classList.add("hidden");
                }
            }
            if (addTemplateBtn) {
                if (role === "admin") {
                    addTemplateBtn.classList.remove("hidden");
                } else {
                    addTemplateBtn.classList.add("hidden");
                }
            }
            if (addTelegramConfigBtn) {
                if (role === "admin") {
                    addTelegramConfigBtn.classList.remove("hidden");
                } else {
                    addTelegramConfigBtn.classList.add("hidden");
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

        // Load and display monitored domains
        async function loadDomains() {
            const tbody = document.getElementById("domains-body");
            if (!tbody) return;
            try {
                const resp = await apiFetch("/v1/domains", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    throw new Error("Failed to load domains");
                }

                const domains = await resp.json();

                if (!domains || domains.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="px-3 py-6 text-center text-xs text-slate-500">No domains in database. Run a scan to add domains.</td></tr>';
                    return;
                }

                tbody.innerHTML = "";
                for (const domain of domains) {
                    const tr = document.createElement("tr");
                    // Add pulse animation for Critical domains
                    if (domain.ssl_status === "Critical") {
                        tr.className = "hover:bg-slate-900/80 transition pulse-critical bg-red-500/10 border-l-4 border-red-500";
                    } else {
                        tr.className = "hover:bg-slate-900/80 transition";
                    }

                    // Domain name with live indicator
                    const domainCell = document.createElement("td");
                    domainCell.className = "px-3 py-2 text-xs font-medium text-slate-100";
                    
                    // Get isLive status and SSL status for this domain
                    const isLive = domain.is_live || false;
                    const sslStatus = domain.ssl_status || "";
                    
                    // Create status indicator dot (breathing/blinking light effect)
                    const liveIndicator = document.createElement("span");
                    liveIndicator.className = "live-indicator";
                    
                    // Determine status: Green (live & SSL safe), Yellow (live but SSL expiring), Red (down)
                    if (!isLive) {
                        // Site is down - blinking red
                        liveIndicator.className += " down";
                        liveIndicator.title = "Site is down";
                    } else if (sslStatus === "Warning" || sslStatus === "Critical") {
                        // Site is live but SSL is expiring - breathing yellow
                        liveIndicator.className += " warning";
                        liveIndicator.title = "Site is live but SSL is expiring";
                    } else {
                        // Site is live and SSL is safe - breathing green
                        liveIndicator.className += " live";
                        liveIndicator.title = "Site is live and SSL is safe";
                    }
                    domainCell.appendChild(liveIndicator);
                    
                    // Add domain name text
                    const domainText = document.createTextNode(domain.domain_name || "-");
                    domainCell.appendChild(domainText);

                    // Live Status
                    const liveStatusCell = document.createElement("td");
                    liveStatusCell.className = "px-3 py-2 text-xs";
                    const statusCode = domain.status_code || 0;
                    const liveStatusIndicator = document.createElement("div");
                    liveStatusIndicator.className = "flex items-center gap-1.5";
                    const liveDot = document.createElement("span");
                    if (isLive && statusCode === 200) {
                        liveDot.className = "h-2 w-2 rounded-full bg-emerald-400";
                        liveStatusIndicator.appendChild(liveDot);
                        const liveText = document.createElement("span");
                        liveText.className = "text-emerald-300 text-[10px]";
                        liveText.textContent = "Live";
                        liveStatusIndicator.appendChild(liveText);
                    } else {
                        liveDot.className = "h-2 w-2 rounded-full bg-red-400";
                        liveStatusIndicator.appendChild(liveDot);
                        const liveText = document.createElement("span");
                        liveText.className = "text-red-300 text-[10px]";
                        if (statusCode > 0) {
                            liveText.textContent = statusCode;
                        } else {
                            liveText.textContent = "Down";
                        }
                        liveStatusIndicator.appendChild(liveText);
                    }
                    liveStatusCell.appendChild(liveStatusIndicator);

                    // SSL Status
                    const sslStatusCell = document.createElement("td");
                    sslStatusCell.className = "px-3 py-2 text-xs";
                    const currentSSLStatus = domain.ssl_status || "Unknown";
                    const sslBadge = document.createElement("span");
                    sslBadge.className = statusBadgeClasses(currentSSLStatus);
                    sslBadge.textContent = currentSSLStatus;
                    sslStatusCell.appendChild(sslBadge);

                    // SSL Expiry
                    const sslExpiryCell = document.createElement("td");
                    sslExpiryCell.className = "px-3 py-2 text-xs text-slate-200";
                    if (domain.ssl_expiry) {
                        const dt = new Date(domain.ssl_expiry);
                        sslExpiryCell.textContent = dt.toLocaleString();
                    } else {
                        sslExpiryCell.textContent = "-";
                    }

                    // Days Remaining
                    const daysCell = document.createElement("td");
                    daysCell.className = "px-3 py-2 text-xs text-slate-200";
                    if (domain.ssl_expiry) {
                        const expiry = new Date(domain.ssl_expiry);
                        const now = new Date();
                        const diffMs = expiry.getTime() - now.getTime();
                        const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
                        daysCell.textContent = diffDays >= 0 ? diffDays : "Expired";
                        // Color code based on days
                        if (diffDays < 7) {
                            daysCell.className = "px-3 py-2 text-xs text-red-400 font-medium";
                        } else if (diffDays < 15) {
                            daysCell.className = "px-3 py-2 text-xs text-amber-400 font-medium";
                        }
                    } else {
                        daysCell.textContent = "-";
                    }

                    // Last Check Time
                    const lastCheckCell = document.createElement("td");
                    lastCheckCell.className = "px-3 py-2 text-xs text-slate-300";
                    if (domain.last_check_time) {
                        const dt = new Date(domain.last_check_time);
                        lastCheckCell.textContent = dt.toLocaleString();
                    } else {
                        lastCheckCell.textContent = "Never";
                    }

                    // Auto-Renew Toggle
                    const autoRenewCell = document.createElement("td");
                    autoRenewCell.className = "px-3 py-2 text-xs";
                    const toggle = document.createElement("label");
                    toggle.className = "relative inline-flex items-center cursor-pointer";
                    const checkbox = document.createElement("input");
                    checkbox.type = "checkbox";
                    checkbox.className = "sr-only peer";
                    checkbox.checked = domain.auto_renew || false;
                    checkbox.addEventListener("change", async function() {
                        try {
                            const resp = await apiFetch("/v1/domains/" + domain.id + "/auto-renew", {
                                method: "PUT",
                                headers: {
                                    "Content-Type": "application/json",
                                    "Accept": "application/json",
                                },
                                body: JSON.stringify({ auto_renew: checkbox.checked }),
                            });
                            if (!resp.ok) {
                                checkbox.checked = !checkbox.checked;
                                alert("Failed to update auto-renew setting");
                            }
                        } catch (err) {
                            checkbox.checked = !checkbox.checked;
                            alert("Error updating auto-renew: " + err.message);
                        }
                    });
                    const slider = document.createElement("div");
                    slider.className = "w-11 h-6 bg-slate-700 peer-focus:outline-none peer-focus:ring-2 peer-focus:ring-emerald-500/70 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-slate-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-emerald-500";
                    toggle.appendChild(checkbox);
                    toggle.appendChild(slider);
                    autoRenewCell.appendChild(toggle);

                    // Actions
                    const actionsCell = document.createElement("td");
                    actionsCell.className = "px-3 py-2 text-xs";
                    const renewBtn = document.createElement("button");
                    renewBtn.className = "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1 text-[10px] text-slate-200 hover:bg-slate-800/80";
                    renewBtn.textContent = "Renew";
                    renewBtn.addEventListener("click", async function() {
                        if (!confirm("Manually renew domain " + domain.domain_name + "?")) return;
                        try {
                            const resp = await apiFetch("/v1/domains/" + domain.id + "/renew", {
                                method: "POST",
                                headers: { "Accept": "application/json" },
                            });
                            const data = await resp.json();
                            alert(data.message || "Renewal initiated");
                        } catch (err) {
                            alert("Error initiating renewal: " + err.message);
                        }
                    });
                    actionsCell.appendChild(renewBtn);

                    tr.appendChild(domainCell);
                    tr.appendChild(liveStatusCell);
                    tr.appendChild(sslStatusCell);
                    tr.appendChild(sslExpiryCell);
                    tr.appendChild(daysCell);
                    tr.appendChild(lastCheckCell);
                    tr.appendChild(autoRenewCell);
                    tr.appendChild(actionsCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error("Error loading domains:", err);
                tbody.innerHTML = '<tr><td colspan="8" class="px-3 py-6 text-center text-xs text-red-400">Error loading domains: ' + (err.message || "Unknown error") + "</td></tr>";
            }
        }

        // Load and display notification configurations
        async function loadNotificationConfigs() {
            const tbody = document.getElementById("notification-configs-body");
            if (!tbody) return;
            try {
                const resp = await apiFetch("/v1/admin/notifications/configs", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    throw new Error("Failed to load notification configs");
                }

                const data = await resp.json();
                const configs = data.configs || [];

                if (configs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No notification configurations. Add one to get started.</td></tr>';
                    return;
                }

                tbody.innerHTML = "";
                for (const config of configs) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    // Platform
                    const platformCell = document.createElement("td");
                    platformCell.className = "px-3 py-2 text-xs font-medium text-slate-100";
                    platformCell.textContent = config.platform || "-";

                    // Webhook URL (truncated)
                    const urlCell = document.createElement("td");
                    urlCell.className = "px-3 py-2 text-xs text-slate-300";
                    const url = config.webhook_url || "-";
                    urlCell.textContent = url.length > 50 ? url.substring(0, 50) + "..." : url;

                    // Status
                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const statusBadge = document.createElement("span");
                    if (config.is_active) {
                        statusBadge.className = "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/40";
                        statusBadge.textContent = "Active";
                    } else {
                        statusBadge.className = "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-700/60 text-slate-300 border border-slate-600/60";
                        statusBadge.textContent = "Inactive";
                    }
                    statusCell.appendChild(statusBadge);

                    // Actions
                    const actionsCell = document.createElement("td");
                    actionsCell.className = "px-3 py-2 text-xs";
                    const deleteBtn = document.createElement("button");
                    deleteBtn.className = "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1 text-[10px] text-rose-300 hover:bg-rose-500/10";
                    deleteBtn.textContent = "Delete";
                    deleteBtn.addEventListener("click", async function() {
                        if (!confirm("Delete this notification configuration?")) return;
                        try {
                            const resp = await apiFetch("/v1/admin/notifications/configs/" + config.id, {
                                method: "DELETE",
                                headers: { "Accept": "application/json" },
                            });
                            if (resp.ok) {
                                loadNotificationConfigs();
                            } else {
                                alert("Failed to delete configuration");
                            }
                        } catch (err) {
                            alert("Error deleting configuration: " + err.message);
                        }
                    });
                    actionsCell.appendChild(deleteBtn);

                    tr.appendChild(platformCell);
                    tr.appendChild(urlCell);
                    tr.appendChild(statusCell);
                    tr.appendChild(actionsCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error("Error loading notification configs:", err);
                tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-red-400">Error loading configs: ' + (err.message || "Unknown error") + "</td></tr>";
            }
        }

        // Load and display message templates
        async function loadMessageTemplates() {
            const tbody = document.getElementById("message-templates-body");
            if (!tbody) return;
            try {
                const resp = await apiFetch("/v1/admin/notifications/templates", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    throw new Error("Failed to load message templates");
                }

                const data = await resp.json();
                const templates = data.templates || [];

                if (templates.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-slate-500">No message templates. Add one to get started.</td></tr>';
                    return;
                }

                tbody.innerHTML = "";
                for (const template of templates) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    // Event Name
                    const eventCell = document.createElement("td");
                    eventCell.className = "px-3 py-2 text-xs font-medium text-slate-100";
                    eventCell.textContent = template.event_name || "-";

                    // Title Template (truncated)
                    const titleCell = document.createElement("td");
                    titleCell.className = "px-3 py-2 text-xs text-slate-300";
                    const title = template.title_template || "-";
                    titleCell.textContent = title.length > 40 ? title.substring(0, 40) + "..." : title;

                    // Body Template (truncated)
                    const bodyCell = document.createElement("td");
                    bodyCell.className = "px-3 py-2 text-xs text-slate-300";
                    const body = template.body_template || "-";
                    bodyCell.textContent = body.length > 40 ? body.substring(0, 40) + "..." : body;

                    // Actions
                    const actionsCell = document.createElement("td");
                    actionsCell.className = "px-3 py-2 text-xs";
                    const deleteBtn = document.createElement("button");
                    deleteBtn.className = "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1 text-[10px] text-rose-300 hover:bg-rose-500/10";
                    deleteBtn.textContent = "Delete";
                    deleteBtn.addEventListener("click", async function() {
                        if (!confirm("Delete this message template?")) return;
                        try {
                            const resp = await apiFetch("/v1/admin/notifications/templates/" + template.id, {
                                method: "DELETE",
                                headers: { "Accept": "application/json" },
                            });
                            if (resp.ok) {
                                loadMessageTemplates();
                            } else {
                                alert("Failed to delete template");
                            }
                        } catch (err) {
                            alert("Error deleting template: " + err.message);
                        }
                    });
                    actionsCell.appendChild(deleteBtn);

                    tr.appendChild(eventCell);
                    tr.appendChild(titleCell);
                    tr.appendChild(bodyCell);
                    tr.appendChild(actionsCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error("Error loading message templates:", err);
                tbody.innerHTML = '<tr><td colspan="4" class="px-3 py-6 text-center text-xs text-red-400">Error loading templates: ' + (err.message || "Unknown error") + "</td></tr>";
            }
        }

        // Load and display Telegram configurations
        async function loadTelegramConfigs() {
            const tbody = document.getElementById("telegram-configs-body");
            if (!tbody) return;
            try {
                const resp = await apiFetch("/v1/admin/notifications/telegram", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    throw new Error("Failed to load Telegram configs");
                }

                const data = await resp.json();
                const configs = data.configs || [];

                if (configs.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="3" class="px-3 py-6 text-center text-xs text-slate-500">No Telegram configurations. Add one to get started.</td></tr>';
                    return;
                }

                tbody.innerHTML = "";
                for (const config of configs) {
                    const tr = document.createElement("tr");
                    tr.className = "hover:bg-slate-900/80 transition";

                    // Chat ID
                    const chatIdCell = document.createElement("td");
                    chatIdCell.className = "px-3 py-2 text-xs font-medium text-slate-100";
                    chatIdCell.textContent = config.tg_chat_id || "-";

                    // Status
                    const statusCell = document.createElement("td");
                    statusCell.className = "px-3 py-2 text-xs";
                    const statusBadge = document.createElement("span");
                    if (config.is_active) {
                        statusBadge.className = "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/40";
                        statusBadge.textContent = "Active";
                    } else {
                        statusBadge.className = "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-slate-700/60 text-slate-300 border border-slate-600/60";
                        statusBadge.textContent = "Inactive";
                    }
                    statusCell.appendChild(statusBadge);

                    // Actions
                    const actionsCell = document.createElement("td");
                    actionsCell.className = "px-3 py-2 text-xs flex items-center gap-2";
                    
                    // Test Connection button
                    const testBtn = document.createElement("button");
                    testBtn.className = "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1 text-[10px] text-sky-300 hover:bg-sky-500/10";
                    testBtn.textContent = "Test";
                    testBtn.addEventListener("click", async function() {
                        testBtn.disabled = true;
                        testBtn.textContent = "Testing...";
                        try {
                            const resp = await apiFetch("/v1/admin/notifications/telegram/" + config.id + "/test", {
                                method: "POST",
                                headers: { "Accept": "application/json" },
                            });
                            if (resp.ok) {
                                alert("Test message sent successfully! Check your Telegram.");
                            } else {
                                const data = await resp.json();
                                alert("Failed to send test message: " + (data.error || data.details || "Unknown error"));
                            }
                        } catch (err) {
                            alert("Error testing connection: " + err.message);
                        } finally {
                            testBtn.disabled = false;
                            testBtn.textContent = "Test";
                        }
                    });
                    actionsCell.appendChild(testBtn);
                    
                    // Delete button
                    const deleteBtn = document.createElement("button");
                    deleteBtn.className = "inline-flex items-center gap-1 rounded-lg border border-slate-700 px-2 py-1 text-[10px] text-rose-300 hover:bg-rose-500/10";
                    deleteBtn.textContent = "Delete";
                    deleteBtn.addEventListener("click", async function() {
                        if (!confirm("Delete this Telegram configuration?")) return;
                        try {
                            const resp = await apiFetch("/v1/admin/notifications/telegram/" + config.id, {
                                method: "DELETE",
                                headers: { "Accept": "application/json" },
                            });
                            if (resp.ok) {
                                loadTelegramConfigs();
                            } else {
                                alert("Failed to delete configuration");
                            }
                        } catch (err) {
                            alert("Error deleting configuration: " + err.message);
                        }
                    });
                    actionsCell.appendChild(deleteBtn);

                    tr.appendChild(chatIdCell);
                    tr.appendChild(statusCell);
                    tr.appendChild(actionsCell);

                    tbody.appendChild(tr);
                }
            } catch (err) {
                console.error("Error loading Telegram configs:", err);
                tbody.innerHTML = '<tr><td colspan="3" class="px-3 py-6 text-center text-xs text-red-400">Error loading configs: ' + (err.message || "Unknown error") + "</td></tr>";
            }
        }

        // Load template editors with current template content
        async function loadTemplateEditors() {
            try {
                const resp = await apiFetch("/v1/admin/notifications/templates", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    throw new Error("Failed to load templates");
                }

                const data = await resp.json();
                const templates = data.templates || [];

                // Find SiteDown template
                const siteDownTemplate = templates.find(t => t.name === "SiteDown" || t.event_name === "SITE_DOWN");
                if (siteDownTemplate) {
                    const textarea = document.getElementById("sitedown-template-text");
                    if (textarea) {
                        textarea.value = siteDownTemplate.template_text || siteDownTemplate.body_template || "";
                        textarea.dataset.templateId = siteDownTemplate.id;
                    }
                }

                // Find SSLExpired template
                const sslExpiredTemplate = templates.find(t => t.name === "SSLExpired" || t.event_name === "SSL_CRITICAL");
                if (sslExpiredTemplate) {
                    const textarea = document.getElementById("sslexpired-template-text");
                    if (textarea) {
                        textarea.value = sslExpiredTemplate.template_text || sslExpiredTemplate.body_template || "";
                        textarea.dataset.templateId = sslExpiredTemplate.id;
                    }
                }
            } catch (err) {
                console.error("Error loading template editors:", err);
            }
        }

        // View switching for sidebar navigation
        // showSection is an alias for setActiveView for compatibility
        function showSection(view) {
            // Map 'settings' to 'notifications' if needed
            if (view === 'settings') {
                view = 'notifications';
            }
            setActiveView(view);
        }

        function setActiveView(view) {
            const views = ["dashboard", "assets", "catalog", "infra", "users", "notifications"];
            
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
                    btn.classList.add("text-slate-300");
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
                selectedBtn.classList.remove("text-slate-300");
            }
            
            // Auto-load data when switching to specific views
            if (view === "dashboard") {
                loadDashboardStats();
            } else if (view === "assets") {
                loadDomains();
            } else if (view === "users") {
                const userSection = document.getElementById("user-management-section");
                if (userSection) {
                    userSection.classList.remove("hidden");
                    userSection.style.display = "";
                }
                loadUsers();
            } else if (view === "notifications") {
                loadNotificationConfigs();
                loadMessageTemplates();
                loadTelegramConfigs();
                loadTemplateEditors();
                // Initialize admin features when notifications view is shown
                if (typeof initAdminFeatures === 'function') {
                    initAdminFeatures();
                }
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
                const resp = await apiFetch("/v1/scan?" + params.toString(), {
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
                const resp = await apiFetch("/v1/projects", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
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
                const resp = await apiFetch("/v1/infra/options", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
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
                const resp = await apiFetch("/v1/infra/provision", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
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
                const resp = await apiFetch("/v1/projects", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
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
                const resp = await apiFetch("/v1/infra", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
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
                const resp = await apiFetch("/v1/infra/status?project=" + encodeURIComponent(projectName), {
                    method: "GET",
                    headers: { "Accept": "application/json" },
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

        // Dashboard charts
        let domainSuffixChart = null;
        let monthlyExpiryChart = null;

        // Load dashboard statistics and render charts
        async function loadDashboardStats() {
            try {
                const resp = await apiFetch("/v1/dashboard/stats", {
                    method: "GET",
                    headers: { "Accept": "application/json" },
                });

                if (!resp.ok) {
                    console.error("Failed to load dashboard stats:", resp.status);
                    return;
                }

                const stats = await resp.json();

                // Update statistic cards
                const totalDomainsEl = document.getElementById("stat-total-domains");
                const sslCriticalEl = document.getElementById("stat-ssl-critical");
                const sslWarningEl = document.getElementById("stat-ssl-warning");
                const projectCountEl = document.getElementById("stat-project-count");
                const globalAvailabilityEl = document.getElementById("stat-global-availability");
                const sitesDownEl = document.getElementById("stat-sites-down");

                if (totalDomainsEl) totalDomainsEl.textContent = stats.total_domains || stats.totalDomains || 0;
                if (sslCriticalEl) sslCriticalEl.textContent = stats.sslCritical || 0;
                if (sslWarningEl) sslWarningEl.textContent = stats.sslWarning || 0;
                if (projectCountEl) projectCountEl.textContent = stats.project_count || 0;
                if (sitesDownEl) sitesDownEl.textContent = stats.sites_down || 0;
                
                // Display global availability as percentage
                if (globalAvailabilityEl) {
                    const availability = stats.global_availability || 0;
                    globalAvailabilityEl.textContent = availability.toFixed(1) + "%";
                    // Color code based on availability
                    if (availability >= 99) {
                        globalAvailabilityEl.className = "text-3xl font-bold text-emerald-400";
                    } else if (availability >= 95) {
                        globalAvailabilityEl.className = "text-3xl font-bold text-amber-400";
                    } else {
                        globalAvailabilityEl.className = "text-3xl font-bold text-red-400";
                    }
                }

                // Render charts with data from API
                if (stats.suffix_distribution) {
                    renderDomainSuffixChart(stats.suffix_distribution);
                }
                if (stats.monthly_expiry) {
                    renderMonthlyExpiryChart(stats.monthly_expiry);
                }
            } catch (err) {
                console.error("Error loading dashboard stats:", err);
            }
        }

        // Render domain suffix distribution doughnut chart
        function renderDomainSuffixChart(suffixDistribution) {
            const ctx = document.getElementById("project-types-chart");
            if (!ctx) return;

            // Sort suffixes by count (descending) and take top 8
            const entries = Object.entries(suffixDistribution);
            entries.sort((a, b) => b[1] - a[1]);
            const topSuffixes = entries.slice(0, 8);
            
            const labels = topSuffixes.map(([suffix]) => suffix || "other");
            const data = topSuffixes.map(([, count]) => count);
            
            const colors = [
                "rgba(16, 185, 129, 0.8)",  // emerald
                "rgba(59, 130, 246, 0.8)",  // sky
                "rgba(251, 191, 36, 0.8)",  // amber
                "rgba(168, 85, 247, 0.8)",  // purple
                "rgba(236, 72, 153, 0.8)",  // pink
                "rgba(34, 197, 94, 0.8)",   // green
                "rgba(249, 115, 22, 0.8)",  // orange
                "rgba(139, 92, 246, 0.8)",  // violet
            ];

            if (domainSuffixChart) {
                domainSuffixChart.destroy();
            }

            domainSuffixChart = new Chart(ctx, {
                type: "doughnut",
                data: {
                    labels: labels,
                    datasets: [{
                        data: data,
                        backgroundColor: colors.slice(0, labels.length),
                        borderColor: "rgba(15, 23, 42, 0.8)",
                        borderWidth: 2,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: "bottom",
                            labels: {
                                color: "rgb(148, 163, 184)",
                                font: { size: 11 },
                            },
                        },
                    },
                },
            });
        }

        // Render monthly expiring domains bar chart
        function renderMonthlyExpiryChart(monthlyExpiry) {
            const ctx = document.getElementById("domain-status-chart");
            if (!ctx) return;

            // Sort months chronologically
            const entries = Object.entries(monthlyExpiry);
            entries.sort((a, b) => a[0].localeCompare(b[0]));
            
            // Format month labels (e.g., "2024-01" -> "Jan 2024")
            const labels = entries.map(([monthKey]) => {
                const [year, month] = monthKey.split("-");
                const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", 
                                   "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
                return monthNames[parseInt(month) - 1] + " " + year;
            });
            const data = entries.map(([, count]) => count);

            if (monthlyExpiryChart) {
                monthlyExpiryChart.destroy();
            }

            monthlyExpiryChart = new Chart(ctx, {
                type: "bar",
                data: {
                    labels: labels,
                    datasets: [{
                        label: "Expiring Domains",
                        data: data,
                        backgroundColor: "rgba(251, 191, 36, 0.8)",  // amber
                        borderColor: "rgba(251, 191, 36, 1)",
                        borderWidth: 1,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false,
                        },
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                color: "rgb(148, 163, 184)",
                                font: { size: 11 },
                                stepSize: 1,
                            },
                            grid: {
                                color: "rgba(51, 65, 85, 0.3)",
                            },
                        },
                        x: {
                            ticks: {
                                color: "rgb(148, 163, 184)",
                                font: { size: 11 },
                            },
                            grid: {
                                color: "rgba(51, 65, 85, 0.3)",
                            },
                        },
                    },
                },
            });
        }

        // Wire up event listeners once the DOM is ready
        document.addEventListener("DOMContentLoaded", function () {
            // Sidebar view switching (with existence checks to prevent blocking login page)
            const navDashboard = document.getElementById("nav-dashboard");
            if (navDashboard) {
                navDashboard.addEventListener("click", function () {
                    setActiveView("dashboard");
                });
            }
            const navAssets = document.getElementById("nav-assets");
            if (navAssets) {
                navAssets.addEventListener("click", function () {
                    setActiveView("assets");
                });
            }
            const navCatalog = document.getElementById("nav-catalog");
            if (navCatalog) {
                navCatalog.addEventListener("click", function () {
                    setActiveView("catalog");
                });
            }
            const navInfra = document.getElementById("nav-infra");
            if (navInfra) {
                navInfra.addEventListener("click", function () {
                    setActiveView("infra");
                });
            }
            const navUsersBtn = document.getElementById("nav-users");
            if (navUsersBtn) {
                navUsersBtn.addEventListener("click", function () {
                    setActiveView("users");
                });
            }

            const navNotificationsBtn = document.getElementById("nav-notifications");
            if (navNotificationsBtn) {
                navNotificationsBtn.addEventListener("click", function () {
                    setActiveView("notifications");
                });
            }

            // Default view - Dashboard
            if (typeof setActiveView === 'function') {
                setActiveView("dashboard");
            }

            // Scanner actions (with existence checks)
            const scanButton = document.getElementById("scan-button");
            if (scanButton) {
                scanButton.addEventListener("click", function () {
                    if (typeof runScan === 'function') {
                        runScan();
                    }
                });
            }
            const domainsInput = document.getElementById("domains-input");
            if (domainsInput) {
                domainsInput.addEventListener("keydown", function (event) {
                    if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
                        event.preventDefault();
                        if (typeof runScan === 'function') {
                            runScan();
                        }
                    }
                });
            }

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

        // Initialize admin features - only called when notifications view is shown
        function initAdminFeatures() {
            // Prevent duplicate initialization
            if (window.adminFeaturesInitialized) {
                return;
            }
            window.adminFeaturesInitialized = true;

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

            // Notification Config Modal Events
            const openNotificationConfigBtn = document.getElementById("open-add-notification-config");
            if (openNotificationConfigBtn) {
                openNotificationConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-notification-config-modal");
                    if (modal) {
                        modal.classList.remove("hidden");
                        modal.classList.add("flex");
                    }
                });
            }
            const closeNotificationConfigBtn = document.getElementById("add-notification-config-close");
            if (closeNotificationConfigBtn) {
                closeNotificationConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-notification-config-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-notification-config-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-notification-config-form");
                    if (form) form.reset();
                });
            }
            const cancelNotificationConfigBtn = document.getElementById("add-notification-config-cancel");
            if (cancelNotificationConfigBtn) {
                cancelNotificationConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-notification-config-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-notification-config-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-notification-config-form");
                    if (form) form.reset();
                });
            }
            const addNotificationConfigForm = document.getElementById("add-notification-config-form");
            if (addNotificationConfigForm) {
                addNotificationConfigForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const platform = (document.getElementById("config-platform").value || "").trim();
                    const webhookURL = (document.getElementById("config-webhook-url").value || "").trim();
                    const secretKey = (document.getElementById("config-secret-key").value || "").trim();
                    const isActive = document.getElementById("config-is-active").checked;
                    const errorEl = document.getElementById("add-notification-config-error");
                    const submitBtn = document.getElementById("add-notification-config-submit");

                    errorEl.textContent = "";
                    if (!platform || !webhookURL) {
                        errorEl.textContent = "Platform and Webhook URL are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.textContent = "Adding...";

                    try {
                        const resp = await apiFetch("/v1/admin/notifications/configs", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                platform: platform,
                                webhook_url: webhookURL,
                                secret_key: secretKey,
                                is_active: isActive,
                            }),
                        });

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to create notification config");
                        }

                        const modal = document.getElementById("add-notification-config-modal");
                        if (modal) {
                            modal.classList.add("hidden");
                            modal.classList.remove("flex");
                        }
                        const form = document.getElementById("add-notification-config-form");
                        if (form) form.reset();
                        loadNotificationConfigs();
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while creating notification config.";
                    } finally {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Add Config";
                    }
                });
            }

            // Message Template Modal Events
            const openTemplateBtn = document.getElementById("open-add-template");
            if (openTemplateBtn) {
                openTemplateBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-template-modal");
                    if (modal) {
                        modal.classList.remove("hidden");
                        modal.classList.add("flex");
                    }
                });
            }
            const closeTemplateBtn = document.getElementById("add-template-close");
            if (closeTemplateBtn) {
                closeTemplateBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-template-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-template-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-template-form");
                    if (form) form.reset();
                });
            }
            const cancelTemplateBtn = document.getElementById("add-template-cancel");
            if (cancelTemplateBtn) {
                cancelTemplateBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-template-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-template-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-template-form");
                    if (form) form.reset();
                });
            }
            const addTemplateForm = document.getElementById("add-template-form");
            if (addTemplateForm) {
                addTemplateForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const eventName = (document.getElementById("template-event-name").value || "").trim();
                    const titleTemplate = (document.getElementById("template-title").value || "").trim();
                    const bodyTemplate = (document.getElementById("template-body").value || "").trim();
                    const errorEl = document.getElementById("add-template-error");
                    const submitBtn = document.getElementById("add-template-submit");

                    errorEl.textContent = "";
                    if (!eventName || !titleTemplate || !bodyTemplate) {
                        errorEl.textContent = "Event name, title template, and body template are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.textContent = "Adding...";

                    try {
                        const resp = await apiFetch("/v1/admin/notifications/templates", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                event_name: eventName,
                                title_template: titleTemplate,
                                body_template: bodyTemplate,
                            }),
                        });

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to create message template");
                        }

                        const modal = document.getElementById("add-template-modal");
                        if (modal) {
                            modal.classList.add("hidden");
                            modal.classList.remove("flex");
                        }
                        const form = document.getElementById("add-template-form");
                        if (form) form.reset();
                        loadMessageTemplates();
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while creating message template.";
                    } finally {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Add Template";
                    }
                });
            }

            // Telegram Config Modal Events
            const openTelegramConfigBtn = document.getElementById("open-add-telegram-config");
            if (openTelegramConfigBtn) {
                openTelegramConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-telegram-config-modal");
                    if (modal) {
                        modal.classList.remove("hidden");
                        modal.classList.add("flex");
                    }
                });
            }
            const closeTelegramConfigBtn = document.getElementById("add-telegram-config-close");
            if (closeTelegramConfigBtn) {
                closeTelegramConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-telegram-config-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-telegram-config-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-telegram-config-form");
                    if (form) form.reset();
                });
            }
            const cancelTelegramConfigBtn = document.getElementById("add-telegram-config-cancel");
            if (cancelTelegramConfigBtn) {
                cancelTelegramConfigBtn.addEventListener("click", function () {
                    const modal = document.getElementById("add-telegram-config-modal");
                    if (modal) {
                        modal.classList.add("hidden");
                        modal.classList.remove("flex");
                    }
                    const errorEl = document.getElementById("add-telegram-config-error");
                    if (errorEl) errorEl.textContent = "";
                    const form = document.getElementById("add-telegram-config-form");
                    if (form) form.reset();
                });
            }
            const addTelegramConfigForm = document.getElementById("add-telegram-config-form");
            if (addTelegramConfigForm) {
                addTelegramConfigForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const token = (document.getElementById("telegram-token").value || "").trim();
                    const chatID = (document.getElementById("telegram-chat-id").value || "").trim();
                    const isActive = document.getElementById("telegram-is-active").checked;
                    const errorEl = document.getElementById("add-telegram-config-error");
                    const submitBtn = document.getElementById("add-telegram-config-submit");

                    errorEl.textContent = "";
                    if (!token || !chatID) {
                        errorEl.textContent = "Bot Token and Chat ID are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.textContent = "Adding...";

                    try {
                        const resp = await apiFetch("/v1/admin/notifications/telegram", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                tg_token: token,
                                tg_chat_id: chatID,
                                is_active: isActive,
                            }),
                        });

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to create Telegram config");
                        }

                        const modal = document.getElementById("add-telegram-config-modal");
                        if (modal) {
                            modal.classList.add("hidden");
                            modal.classList.remove("flex");
                        }
                        const form = document.getElementById("add-telegram-config-form");
                        if (form) form.reset();
                        loadTelegramConfigs();
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while creating Telegram config.";
                    } finally {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Add Config";
                    }
                });
            }

            // Telegram Config Form (in Notifications view)
            const telegramConfigForm = document.getElementById("telegram-config-form");
            if (telegramConfigForm) {
                telegramConfigForm.addEventListener("submit", async function (event) {
                    event.preventDefault();
                    const token = (document.getElementById("tg-bot-token").value || "").trim();
                    const chatID = (document.getElementById("tg-chat-id").value || "").trim();
                    const isActive = document.getElementById("tg-is-active").checked;
                    const errorEl = document.getElementById("telegram-config-error");
                    const successEl = document.getElementById("telegram-config-success");
                    const submitBtn = document.getElementById("save-telegram-config-btn");

                    errorEl.textContent = "";
                    successEl.textContent = "";
                    
                    if (!token || !chatID) {
                        errorEl.textContent = "Bot Token and Chat ID are required.";
                        return;
                    }

                    submitBtn.disabled = true;
                    submitBtn.textContent = "Saving...";

                    try {
                        // Check if config exists (load existing configs first)
                        const listResp = await apiFetch("/v1/admin/notifications/telegram", {
                            method: "GET",
                            headers: { "Accept": "application/json" },
                        });
                        
                        let configId = null;
                        if (listResp.ok) {
                            const listData = await listResp.json();
                            const existingConfig = listData.configs && listData.configs[0];
                            if (existingConfig) {
                                configId = existingConfig.id;
                            }
                        }

                        let resp;
                        if (configId) {
                            // Update existing config
                            resp = await apiFetch("/v1/admin/notifications/telegram/" + configId, {
                                method: "PUT",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({
                                    tg_token: token,
                                    tg_chat_id: chatID,
                                    is_active: isActive,
                                }),
                            });
                        } else {
                            // Create new config
                            resp = await apiFetch("/v1/admin/notifications/telegram", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({
                                    tg_token: token,
                                    tg_chat_id: chatID,
                                    is_active: isActive,
                                }),
                            });
                        }

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to save Telegram config");
                        }

                        successEl.textContent = "Telegram configuration saved successfully!";
                        loadTelegramConfigs();
                        
                        // Clear form after a delay
                        setTimeout(() => {
                            successEl.textContent = "";
                        }, 3000);
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Unexpected error while saving Telegram config.";
                    } finally {
                        submitBtn.disabled = false;
                        submitBtn.textContent = "Save Config";
                    }
                });
            }

            // Test Telegram Notification Button
            const testTelegramBtn = document.getElementById("test-telegram-btn");
            if (testTelegramBtn) {
                testTelegramBtn.addEventListener("click", async function () {
                    const token = (document.getElementById("tg-bot-token").value || "").trim();
                    const chatID = (document.getElementById("tg-chat-id").value || "").trim();
                    const errorEl = document.getElementById("telegram-config-error");
                    const successEl = document.getElementById("telegram-config-success");

                    errorEl.textContent = "";
                    successEl.textContent = "";

                    if (!token || !chatID) {
                        errorEl.textContent = "Please enter Bot Token and Chat ID first.";
                        return;
                    }

                    testTelegramBtn.disabled = true;
                    testTelegramBtn.textContent = "Testing...";

                    try {
                        // First, check if config exists
                        const listResp = await apiFetch("/v1/admin/notifications/telegram", {
                            method: "GET",
                            headers: { "Accept": "application/json" },
                        });
                        
                        let configId = null;
                        if (listResp.ok) {
                            const listData = await listResp.json();
                            const existingConfig = listData.configs && listData.configs[0];
                            if (existingConfig && existingConfig.tg_token === token && existingConfig.tg_chat_id === chatID) {
                                configId = existingConfig.id;
                            }
                        }

                        if (configId) {
                            // Use existing config ID
                            const resp = await apiFetch("/v1/admin/notifications/telegram/" + configId + "/test", {
                                method: "POST",
                                headers: { "Accept": "application/json" },
                            });

                            if (!resp.ok) {
                                const data = await resp.json();
                                throw new Error(data.error || data.details || "Failed to send test message");
                            }

                            successEl.textContent = "Test message sent successfully! Check your Telegram.";
                        } else {
                            // Send test message directly using the token and chat ID from form
                            // We'll use a temporary approach: create a config, test it, then optionally delete it
                            const testMessage = "Hello from ZenStack";
                            
                            // Import notify function would be ideal, but we can call the API endpoint
                            // For now, let's create a temporary config and test it
                            const createResp = await apiFetch("/v1/admin/notifications/telegram", {
                                method: "POST",
                                headers: { "Content-Type": "application/json" },
                                body: JSON.stringify({
                                    tg_token: token,
                                    tg_chat_id: chatID,
                                    is_active: true,
                                }),
                            });

                            if (!createResp.ok) {
                                const data = await createResp.json();
                                throw new Error(data.error || "Failed to create test config");
                            }

                            const newConfig = await createResp.json();
                            
                            // Test the connection
                            const testResp = await apiFetch("/v1/admin/notifications/telegram/" + newConfig.id + "/test", {
                                method: "POST",
                                headers: { "Accept": "application/json" },
                            });

                            if (!testResp.ok) {
                                // Delete the temp config if test fails
                                await apiFetch("/v1/admin/notifications/telegram/" + newConfig.id, {
                                    method: "DELETE",
                                });
                                const data = await testResp.json();
                                throw new Error(data.error || data.details || "Failed to send test message");
                            }

                            successEl.textContent = "Test message sent successfully! Check your Telegram.";
                            loadTelegramConfigs();
                        }
                    } catch (err) {
                        console.error(err);
                        errorEl.textContent = err.message || "Error testing Telegram connection.";
                    } finally {
                        testTelegramBtn.disabled = false;
                        testTelegramBtn.textContent = "Test TG Notification";
                    }
                });
            }

            // Template Editor Save Buttons
            const saveSiteDownBtn = document.getElementById("save-sitedown-template");
            if (saveSiteDownBtn) {
                saveSiteDownBtn.addEventListener("click", async function () {
                    const textarea = document.getElementById("sitedown-template-text");
                    if (!textarea) return;
                    
                    const templateId = textarea.dataset.templateId;
                    if (!templateId) {
                        alert("Template ID not found. Please refresh the page.");
                        return;
                    }

                    const templateText = textarea.value.trim();
                    if (!templateText) {
                        alert("Template text cannot be empty.");
                        return;
                    }

                    saveSiteDownBtn.disabled = true;
                    saveSiteDownBtn.textContent = "Saving...";

                    try {
                        const resp = await apiFetch("/v1/admin/notifications/templates/" + templateId, {
                            method: "PUT",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                template_text: templateText,
                            }),
                        });

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to update template");
                        }

                        alert("Site Down template saved successfully!");
                    } catch (err) {
                        console.error(err);
                        alert("Error saving template: " + err.message);
                    } finally {
                        saveSiteDownBtn.disabled = false;
                        saveSiteDownBtn.textContent = "Save";
                    }
                });
            }

            const saveSSLExpiredBtn = document.getElementById("save-sslexpired-template");
            if (saveSSLExpiredBtn) {
                saveSSLExpiredBtn.addEventListener("click", async function () {
                    const textarea = document.getElementById("sslexpired-template-text");
                    if (!textarea) return;
                    
                    const templateId = textarea.dataset.templateId;
                    if (!templateId) {
                        alert("Template ID not found. Please refresh the page.");
                        return;
                    }

                    const templateText = textarea.value.trim();
                    if (!templateText) {
                        alert("Template text cannot be empty.");
                        return;
                    }

                    saveSSLExpiredBtn.disabled = true;
                    saveSSLExpiredBtn.textContent = "Saving...";

                    try {
                        const resp = await apiFetch("/v1/admin/notifications/templates/" + templateId, {
                            method: "PUT",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({
                                template_text: templateText,
                            }),
                        });

                        if (!resp.ok) {
                            const data = await resp.json();
                            throw new Error(data.error || "Failed to update template");
                        }

                        alert("SSL Expiring template saved successfully!");
                    } catch (err) {
                        console.error(err);
                        alert("Error saving template: " + err.message);
                    } finally {
                        saveSSLExpiredBtn.disabled = false;
                        saveSSLExpiredBtn.textContent = "Save";
                    }
                });
            }
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

            const refreshDomainsBtn = document.getElementById("refresh-domains");
            if (refreshDomainsBtn) {
                refreshDomainsBtn.addEventListener("click", loadDomains);
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

            // Initialize login form - independent function that doesn't depend on admin pages
            function initLogin() {
                const loginForm = document.getElementById("login-form");
                if (loginForm) {
                    loginForm.addEventListener("submit", async function (event) {
                        event.preventDefault();
                        const usernameEl = document.getElementById("login-username");
                        const passwordEl = document.getElementById("login-password");
                        const errorEl = document.getElementById("login-error");
                        const submitBtn = document.getElementById("login-submit");

                        if (!usernameEl || !passwordEl || !errorEl || !submitBtn) {
                            console.error("Login form elements not found");
                            return;
                        }

                        const username = (usernameEl.value || "").trim();
                        const password = (passwordEl.value || "").trim();

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
                            // Switch to dashboard view after login
                            setActiveView("dashboard");
                            // Also call showSection for compatibility if it exists
                            if (typeof showSection === 'function') {
                                showSection('dashboard');
                            }
                            // Load initial data after login
                            if (typeof loadProjects === 'function') loadProjects();
                            if (typeof loadInfraOptions === 'function') loadInfraOptions();
                            if (typeof loadInfraResources === 'function') loadInfraResources();
                        } catch (err) {
                            console.error(err);
                            errorEl.textContent = err.message || "Unexpected error while logging in.";
                        } finally {
                            submitBtn.disabled = false;
                        }
                    });
                }
            }

            // Initialize login immediately (doesn't depend on admin pages)
            initLogin();

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

// handleDashboardStats returns dashboard statistics for admin users
func handleDashboardStats(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	// Calculate total domains
	var totalDomains int64
	database.DB.Model(&database.MonitoredDomain{}).Count(&totalDomains)

	// Calculate SSL critical domains - count by ssl_status field dynamically
	var sslCritical int64
	database.DB.Model(&database.MonitoredDomain{}).
		Where("ssl_status = ?", "Critical").
		Count(&sslCritical)

	// Calculate SSL warning domains - count by ssl_status field dynamically
	var sslWarning int64
	database.DB.Model(&database.MonitoredDomain{}).
		Where("ssl_status = ?", "Warning").
		Count(&sslWarning)

	// Calculate domains expiring in the next 30 days (for backward compatibility)
	var expiringSoonCount int64
	thirtyDaysFromNow := time.Now().AddDate(0, 0, 30)
	database.DB.Model(&database.MonitoredDomain{}).
		Where("last_expiry_date <= ? AND last_expiry_date >= ?", thirtyDaysFromNow, time.Now()).
		Count(&expiringSoonCount)

	// Calculate total projects
	var projectCount int64
	database.DB.Model(&database.Project{}).Count(&projectCount)

	// Calculate active users
	var activeUsers int64
	database.DB.Model(&database.User{}).Where("status = ?", "active").Count(&activeUsers)

	// Calculate global availability (percentage of live domains)
	var totalLive int64
	database.DB.Model(&database.MonitoredDomain{}).Where("is_live = ?", true).Count(&totalLive)
	var globalAvailability float64
	if totalDomains > 0 {
		globalAvailability = float64(totalLive) / float64(totalDomains) * 100.0
	}

	// Calculate sites down (domains that are not live)
	var sitesDown int64
	database.DB.Model(&database.MonitoredDomain{}).Where("is_live = ?", false).Count(&sitesDown)

	// Get all domains for suffix distribution and monthly expiry analysis
	var domains []database.MonitoredDomain
	database.DB.Find(&domains)

	// Calculate domain suffix distribution
	suffixCounts := make(map[string]int)
	for _, domain := range domains {
		suffix := extractDomainSuffix(domain.DomainName)
		suffixCounts[suffix]++
	}

	// Convert suffix counts to map for JSON response
	suffixDistribution := make(map[string]int)
	for suffix, count := range suffixCounts {
		suffixDistribution[suffix] = count
	}

	// Calculate monthly expiring domains (next 12 months) based on SSL expiry
	monthlyExpiry := make(map[string]int)
	now := time.Now()
	for i := 0; i < 12; i++ {
		monthStart := time.Date(now.Year(), now.Month()+time.Month(i), 1, 0, 0, 0, 0, now.Location())
		monthEnd := monthStart.AddDate(0, 1, 0).Add(-time.Second)
		monthKey := monthStart.Format("2006-01")

		var count int64
		database.DB.Model(&database.MonitoredDomain{}).
			Where("ssl_expiry >= ? AND ssl_expiry <= ?", monthStart, monthEnd).
			Count(&count)
		monthlyExpiry[monthKey] = int(count)
	}

	c.JSON(http.StatusOK, gin.H{
		"total_domains":       totalDomains,
		"totalDomains":        totalDomains, // Alias for consistency
		"sslCritical":         sslCritical,
		"sslWarning":          sslWarning,
		"expiring_soon_count": expiringSoonCount,
		"project_count":       projectCount,
		"active_users":        activeUsers,
		"global_availability": globalAvailability,
		"total_live":          totalLive,
		"sites_down":          sitesDown,
		"suffix_distribution": suffixDistribution,
		"monthly_expiry":      monthlyExpiry,
	})
}

// extractDomainSuffix extracts the TLD suffix from a domain name (e.g., "example.com" -> ".com")
func extractDomainSuffix(domainName string) string {
	parts := strings.Split(domainName, ".")
	if len(parts) < 2 {
		return "other"
	}
	// Get the last part as the suffix
	suffix := "." + parts[len(parts)-1]
	// Handle common suffixes
	if suffix == ".com" || suffix == ".net" || suffix == ".org" || suffix == ".io" ||
		suffix == ".jp" || suffix == ".cn" || suffix == ".co" || suffix == ".dev" {
		return suffix
	}
	// For other suffixes, return as is
	return suffix
}

// handleListDomains returns all monitored domains from the database
func handleListDomains(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "database not initialized",
		})
		return
	}

	var domains []database.MonitoredDomain
	if err := database.DB.Order("created_at desc").Find(&domains).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "failed to fetch domains",
		})
		return
	}

	c.JSON(http.StatusOK, domains)
}

// handleUpdateAutoRenew updates the auto-renew setting for a domain
func handleUpdateAutoRenew(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain ID is required"})
		return
	}

	var body struct {
		AutoRenew bool `json:"auto_renew"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	var domain database.MonitoredDomain
	if err := database.DB.First(&domain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}

	if err := database.DB.Model(&domain).Update("auto_renew", body.AutoRenew).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update auto-renew setting"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         domain.ID,
		"auto_renew": body.AutoRenew,
	})
}

// handleManualRenew attempts to manually renew a domain (placeholder for third-party API integration)
func handleManualRenew(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "domain ID is required"})
		return
	}

	var domain database.MonitoredDomain
	if err := database.DB.First(&domain, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "domain not found"})
		return
	}

	// TODO: Integrate with GoDaddy or Cloudflare API for actual renewal
	// For now, this is a placeholder that just returns a success message
	// In a real implementation, you would:
	// 1. Check if API keys are configured
	// 2. Call the registrar's API to renew the domain
	// 3. Update the domain's expiry date in the database

	c.JSON(http.StatusOK, gin.H{
		"message": "Manual renewal initiated (placeholder - API integration required)",
		"domain":  domain.DomainName,
		"note":    "This endpoint requires GoDaddy or Cloudflare API key configuration",
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

		// Save or update domain in database
		if database.DB != nil {
			sslStatus := getSSLStatus(result.DaysRemaining)
			now := time.Now()

			var existingDomain database.MonitoredDomain
			err := database.DB.Where("domain_name = ?", result.DomainName).First(&existingDomain).Error

			updateData := map[string]interface{}{
				"ssl_expiry":      result.ExpiryDate,
				"ssl_status":      sslStatus,
				"last_check_time": now,
				"status":          status,
			}

			if !result.DomainExpiryDate.IsZero() {
				updateData["last_expiry_date"] = result.DomainExpiryDate
			}

			if result.Registrar != "" {
				updateData["registrar"] = result.Registrar
			}

			if err != nil {
				// Domain doesn't exist, create new
				newDomain := database.MonitoredDomain{
					DomainName:     result.DomainName,
					SSLExpiry:      result.ExpiryDate,
					SSLStatus:      sslStatus,
					LastCheckTime:  now,
					Status:         status,
					LastExpiryDate: result.DomainExpiryDate,
					Registrar:      result.Registrar,
					AutoRenew:      false,
				}
				database.DB.Create(&newDomain)
			} else {
				// Update existing domain
				database.DB.Model(&existingDomain).Updates(updateData)
			}
		}

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

// deepScanSSL performs a deep SSL certificate scan using tls.DialWithDialer with 5s timeout
func deepScanSSL(domainName string) SSLScanResult {
	// Set a connection timeout to 5 seconds
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Connect to port 443 (HTTPS)
	// InsecureSkipVerify is set to true to fetch info even if the cert is expired
	conn, err := tls.DialWithDialer(dialer, "tcp", domainName+":443", &tls.Config{
		InsecureSkipVerify: true,
	})

	if err != nil {
		return SSLScanResult{
			DomainName:    domainName,
			IsReachable:   false,
			DaysRemaining: -1,
		}
	}
	defer conn.Close()

	// Get the first certificate in the peer chain
	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return SSLScanResult{
			DomainName:    domainName,
			IsReachable:   false,
			DaysRemaining: -1,
		}
	}

	cert := conn.ConnectionState().PeerCertificates[0]

	// Parse PeerCertificates[0].NotAfter to get SSL expiry
	expiryUTC := cert.NotAfter
	expiryLocal := expiryUTC.In(time.Local)

	// Calculate days remaining using math.Ceil for more intuitive countdown
	daysRemaining := int(math.Ceil(time.Until(expiryLocal).Hours() / 24))

	return SSLScanResult{
		DomainName:    domainName,
		ExpiryDate:    expiryLocal,
		DaysRemaining: daysRemaining,
		IsReachable:   true,
	}
}

// getSSLStatus determines the SSL status based on days remaining
func getSSLStatus(daysRemaining int) string {
	if daysRemaining < 0 {
		return "Expired"
	}
	if daysRemaining < 7 {
		return "Critical"
	}
	if daysRemaining < 15 {
		return "Warning"
	}
	return "Valid"
}

// startSSLScanner runs in the background and scans all domains every 6 hours
func startSSLScanner() {
	// Run immediately on startup, then every 6 hours
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	// Initial scan
	scanAllDomainsSSL()

	// Periodic scans
	for range ticker.C {
		scanAllDomainsSSL()
	}
}

// scanSSLTask is an alias for backward compatibility
func scanSSLTask() {
	startSSLScanner()
}

// scanAllDomainsSSL scans all domains in the database and updates SSL information
func scanAllDomainsSSL() {
	if database.DB == nil {
		log.Println("Database not initialized, skipping SSL scan")
		return
	}

	log.Println("Starting background SSL certificate scan...")

	var domains []database.MonitoredDomain
	if err := database.DB.Find(&domains).Error; err != nil {
		log.Printf("Error fetching domains for SSL scan: %v", err)
		return
	}

	if len(domains) == 0 {
		log.Println("No domains to scan")
		return
	}

	log.Printf("Scanning %d domains for SSL certificates...", len(domains))

	// Scan domains with a worker pool
	jobs := make(chan database.MonitoredDomain, len(domains))
	results := make(chan struct {
		domain database.MonitoredDomain
		result SSLScanResult
	}, len(domains))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				result := deepScanSSL(d.DomainName)
				results <- struct {
					domain database.MonitoredDomain
					result SSLScanResult
				}{domain: d, result: result}
			}
		}()
	}

	// Send jobs
	for _, d := range domains {
		jobs <- d
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	updated := 0
	for res := range results {
		sslStatus := getSSLStatus(res.result.DaysRemaining)
		now := time.Now()

		updateData := map[string]interface{}{
			"ssl_expiry":      res.result.ExpiryDate,
			"ssl_status":      sslStatus,
			"last_check_time": now,
		}

		// If domain is not reachable, set status to "Offline"
		if !res.result.IsReachable {
			updateData["ssl_status"] = "Offline"
		}

		if err := database.DB.Model(&res.domain).Updates(updateData).Error; err != nil {
			log.Printf("Error updating domain %s: %v", res.domain.DomainName, err)
		} else {
			updated++

			// Check if we need to send a notification for SSL Expiring (days remaining < 7)
			if res.result.DaysRemaining < 7 && res.result.DaysRemaining >= 0 {
				// Reload domain to get updated SSL status
				var updatedDomain database.MonitoredDomain
				if err := database.DB.First(&updatedDomain, res.domain.ID).Error; err == nil {
					// Check if notification was sent in the last 24 hours
					shouldNotify := false
					if updatedDomain.LastNotificationSent.IsZero() {
						// Never sent a notification before
						shouldNotify = true
					} else {
						// Check if 24 hours have passed since last notification
						timeSinceLastNotification := now.Sub(updatedDomain.LastNotificationSent)
						if timeSinceLastNotification >= 24*time.Hour {
							shouldNotify = true
						}
					}

					if shouldNotify {
						// Get message template for SSL Risk event
						var template database.MessageTemplate
						if err := database.DB.Where("event_name = ? OR name = ?", "SSL_CRITICAL", "SSLExpired").First(&template).Error; err == nil {
							// Prepare data for template
							data := map[string]string{
								"domain":         updatedDomain.DomainName,
								"days":           fmt.Sprintf("%d", res.result.DaysRemaining),
								"days_remaining": fmt.Sprintf("%d", res.result.DaysRemaining),
								"expiry":         updatedDomain.SSLExpiry.Format("2006-01-02 15:04:05"),
								"expiry_date":    updatedDomain.SSLExpiry.Format("2006-01-02"),
							}

							// Format template text
							telegramText := notify.ParseTemplate(template.TemplateText, data)
							if telegramText == "" {
								// Fallback message if template is empty
								telegramText = fmt.Sprintf("🔒 证书预警：域名 %s 的 SSL 证书将在 %d 天后过期。", updatedDomain.DomainName, res.result.DaysRemaining)
							}

							// Send to Telegram using sendTelegramAlert function
							if err := notify.SendTelegramAlert(telegramText); err != nil {
								log.Printf("Failed to send Telegram notification for domain %s: %v", updatedDomain.DomainName, err)
							} else {
								log.Printf("Telegram notification sent for SSL Risk domain: %s (Days: %d)", updatedDomain.DomainName, res.result.DaysRemaining)
								// Update last_notification_sent timestamp
								database.DB.Model(&updatedDomain).Update("last_notification_sent", now)
							}
						} else {
							log.Printf("No template found for SSL Risk event, using default message")
							// Send default message if no template found
							defaultMessage := fmt.Sprintf("🔒 证书预警：域名 %s 的 SSL 证书将在 %d 天后过期。", updatedDomain.DomainName, res.result.DaysRemaining)
							if err := notify.SendTelegramAlert(defaultMessage); err != nil {
								log.Printf("Failed to send Telegram notification for domain %s: %v", updatedDomain.DomainName, err)
							}
						}
					}
				}
			}
		}
	}

	log.Printf("SSL scan completed. Updated %d/%d domains", updated, len(domains))
}

// HealthCheckResult represents the result of an HTTP health check
type HealthCheckResult struct {
	DomainName   string
	IsLive       bool
	StatusCode   int
	ResponseTime int // in milliseconds
}

// checkDomainHealth performs an HTTP health check on a domain using http.Get
// Uses http.Client with 5s timeout to make GET requests
func checkDomainHealth(domainName string) HealthCheckResult {
	startTime := time.Now()

	// Try HTTPS first, then HTTP
	urls := []string{
		"https://" + domainName,
		"http://" + domainName,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, urlStr := range urls {
		// Use http.Get as requested
		resp, err := client.Get(urlStr)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		// Calculate response time
		responseTime := int(time.Since(startTime).Milliseconds())

		// Consider 2xx and 3xx status codes as "live"
		isLive := resp.StatusCode >= 200 && resp.StatusCode < 400

		return HealthCheckResult{
			DomainName:   domainName,
			IsLive:       isLive,
			StatusCode:   resp.StatusCode,
			ResponseTime: responseTime,
		}
	}

	// If both HTTPS and HTTP failed, domain is not live
	return HealthCheckResult{
		DomainName:   domainName,
		IsLive:       false,
		StatusCode:   0,
		ResponseTime: int(time.Since(startTime).Milliseconds()),
	}
}

// startLiveMonitor runs in the background and checks domain health every 2 minutes
// It performs HTTP GET requests to check if domains are live and updates IsLive and LastStatusCode
func startLiveMonitor() {
	// Run immediately on startup
	checkAllDomainsHealth()

	// Use a ticker that runs every 2 minutes
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	// Periodic checks
	for range ticker.C {
		checkAllDomainsHealth()
	}
}

// checkSiteLive is an alias for startLiveMonitor (backward compatibility)
func checkSiteLive() {
	startLiveMonitor()
}

// startHealthCheck is an alias for checkSiteLive (backward compatibility)
func startHealthCheck() {
	checkSiteLive()
}

// startHealthChecker is an alias for startHealthCheck (backward compatibility)
func startHealthChecker() {
	startHealthCheck()
}

// checkAllDomainsHealth checks the HTTP health of all domains in the database
func checkAllDomainsHealth() {
	if database.DB == nil {
		log.Println("Database not initialized, skipping health check")
		return
	}

	log.Println("Starting background HTTP health check...")

	var domains []database.MonitoredDomain
	if err := database.DB.Find(&domains).Error; err != nil {
		log.Printf("Error fetching domains for health check: %v", err)
		return
	}

	if len(domains) == 0 {
		log.Println("No domains to check")
		return
	}

	log.Printf("Checking HTTP health for %d domains...", len(domains))

	// Check domains with a worker pool
	jobs := make(chan database.MonitoredDomain, len(domains))
	results := make(chan struct {
		domain database.MonitoredDomain
		result HealthCheckResult
	}, len(domains))

	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range jobs {
				result := checkDomainHealth(d.DomainName)
				results <- struct {
					domain database.MonitoredDomain
					result HealthCheckResult
				}{domain: d, result: result}
			}
		}()
	}

	// Send jobs
	for _, d := range domains {
		jobs <- d
	}
	close(jobs)

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	updated := 0
	for res := range results {
		// Track previous state to detect transitions from Live to Down
		wasLive := res.domain.IsLive
		nowLive := res.result.IsLive

		updateData := map[string]interface{}{
			"is_live":          res.result.IsLive,
			"status_code":      res.result.StatusCode,
			"last_status_code": res.result.StatusCode, // Update LastStatusCode
			"response_time":    res.result.ResponseTime,
		}

		if err := database.DB.Model(&res.domain).Updates(updateData).Error; err != nil {
			log.Printf("Error updating domain health %s: %v", res.domain.DomainName, err)
		} else {
			updated++

			// Trigger Telegram notification if site transitions from Live to Down
			if wasLive && !nowLive {
				// Site went from Live to Down - immediately send Telegram notification
				log.Printf("Domain %s transitioned from Live to Down, sending Telegram notification", res.domain.DomainName)

				// Get message template for SITE_DOWN event
				var template database.MessageTemplate
				if err := database.DB.Where("event_name = ? OR name = ?", "SITE_DOWN", "SiteDown").First(&template).Error; err == nil {
					// Prepare data for template
					data := map[string]string{
						"domain":      res.domain.DomainName,
						"status":      fmt.Sprintf("%d", res.result.StatusCode),
						"status_code": fmt.Sprintf("%d", res.result.StatusCode),
						"code":        fmt.Sprintf("%d", res.result.StatusCode), // Alias for code variable
					}

					// Format template text
					telegramText := notify.ParseTemplate(template.TemplateText, data)
					if telegramText == "" {
						// Fallback message if template is empty
						telegramText = fmt.Sprintf("🚨 告警：站点 %s 无法访问！状态码：%d", res.domain.DomainName, res.result.StatusCode)
					}

					// Send to Telegram using sendTelegramAlert function
					// sendTelegramAlert automatically reads config from database
					if err := notify.SendTelegramAlert(telegramText); err != nil {
						log.Printf("Failed to send Telegram notification for domain %s: %v", res.domain.DomainName, err)
					} else {
						log.Printf("Telegram notification sent for domain %s (Live -> Down)", res.domain.DomainName)
					}
				} else {
					log.Printf("No template found for SITE_DOWN event, using default message")
					// Send default message if no template found
					defaultMessage := fmt.Sprintf("🚨 告警：站点 %s 无法访问！状态码：%d", res.domain.DomainName, res.result.StatusCode)
					if err := notify.SendTelegramAlert(defaultMessage); err != nil {
						log.Printf("Failed to send Telegram notification for domain %s: %v", res.domain.DomainName, err)
					}
				}
			}
		}
	}

	log.Printf("Health check completed. Updated %d/%d domains", updated, len(domains))
}

// Notification Configuration Handlers

// handleListNotificationConfigs returns all notification configurations
func handleListNotificationConfigs(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var configs []database.NotificationConfig
	if err := database.DB.Order("created_at desc").Find(&configs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list notification configs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// handleCreateNotificationConfig creates a new notification configuration
func handleCreateNotificationConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var body struct {
		WebhookURL string `json:"webhook_url"`
		SecretKey  string `json:"secret_key"`
		Platform   string `json:"platform"`
		IsActive   bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if body.WebhookURL == "" || body.Platform == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "webhook_url and platform are required"})
		return
	}

	config := database.NotificationConfig{
		WebhookURL: body.WebhookURL,
		SecretKey:  body.SecretKey,
		Platform:   body.Platform,
		IsActive:   body.IsActive,
	}

	if err := database.DB.Create(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create notification config"})
		return
	}

	c.JSON(http.StatusCreated, config)
}

// handleUpdateNotificationConfig updates an existing notification configuration
func handleUpdateNotificationConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config ID is required"})
		return
	}

	var config database.NotificationConfig
	if err := database.DB.First(&config, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "notification config not found"})
		return
	}

	var body struct {
		WebhookURL string `json:"webhook_url"`
		SecretKey  string `json:"secret_key"`
		Platform   string `json:"platform"`
		IsActive   bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	updateData := map[string]interface{}{
		"platform":  body.Platform,
		"is_active": body.IsActive,
	}

	if body.WebhookURL != "" {
		updateData["webhook_url"] = body.WebhookURL
	}
	if body.SecretKey != "" {
		updateData["secret_key"] = body.SecretKey
	}

	if err := database.DB.Model(&config).Updates(updateData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update notification config"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// handleDeleteNotificationConfig deletes a notification configuration
func handleDeleteNotificationConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config ID is required"})
		return
	}

	if err := database.DB.Delete(&database.NotificationConfig{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete notification config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "notification config deleted"})
}

// Message Template Handlers

// handleListMessageTemplates returns all message templates
func handleListMessageTemplates(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var templates []database.MessageTemplate
	if err := database.DB.Order("created_at desc").Find(&templates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list message templates"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"templates": templates})
}

// handleCreateMessageTemplate creates a new message template
func handleCreateMessageTemplate(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var body struct {
		EventName     string `json:"event_name"`
		TitleTemplate string `json:"title_template"`
		BodyTemplate  string `json:"body_template"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if body.EventName == "" || body.TitleTemplate == "" || body.BodyTemplate == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "event_name, title_template, and body_template are required"})
		return
	}

	template := database.MessageTemplate{
		EventName:     body.EventName,
		TitleTemplate: body.TitleTemplate,
		BodyTemplate:  body.BodyTemplate,
	}

	if err := database.DB.Create(&template).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusConflict, gin.H{"error": "template for this event already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create message template"})
		return
	}

	c.JSON(http.StatusCreated, template)
}

// handleUpdateMessageTemplate updates an existing message template
func handleUpdateMessageTemplate(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "template ID is required"})
		return
	}

	var template database.MessageTemplate
	if err := database.DB.First(&template, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "message template not found"})
		return
	}

	var body struct {
		EventName     string `json:"event_name"`
		TitleTemplate string `json:"title_template"`
		BodyTemplate  string `json:"body_template"`
		TemplateText  string `json:"template_text"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	updateData := map[string]interface{}{}
	if body.EventName != "" {
		updateData["event_name"] = body.EventName
	}
	if body.TitleTemplate != "" {
		updateData["title_template"] = body.TitleTemplate
	}
	if body.BodyTemplate != "" {
		updateData["body_template"] = body.BodyTemplate
	}
	if body.TemplateText != "" {
		updateData["template_text"] = body.TemplateText
	}

	if err := database.DB.Model(&template).Updates(updateData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update message template"})
		return
	}

	c.JSON(http.StatusOK, template)
}

// handleDeleteMessageTemplate deletes a message template
func handleDeleteMessageTemplate(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "template ID is required"})
		return
	}

	if err := database.DB.Delete(&database.MessageTemplate{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete message template"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "message template deleted"})
}

// Telegram Notification Config Handlers

// handleListTelegramConfigs returns all Telegram notification configurations
func handleListTelegramConfigs(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var configs []database.NotifyConfig
	if err := database.DB.Order("created_at desc").Find(&configs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list telegram configs"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"configs": configs})
}

// handleCreateTelegramConfig creates a new Telegram notification configuration
func handleCreateTelegramConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var body struct {
		TGToken  string `json:"tg_token"`
		TGChatID string `json:"tg_chat_id"`
		IsActive bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if body.TGToken == "" || body.TGChatID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tg_token and tg_chat_id are required"})
		return
	}

	config := database.NotifyConfig{
		TGToken:  body.TGToken,
		TGChatID: body.TGChatID,
		IsActive: body.IsActive,
	}

	if err := database.DB.Create(&config).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create telegram config"})
		return
	}

	c.JSON(http.StatusCreated, config)
}

// handleUpdateTelegramConfig updates an existing Telegram notification configuration
func handleUpdateTelegramConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config ID is required"})
		return
	}

	var config database.NotifyConfig
	if err := database.DB.First(&config, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "telegram config not found"})
		return
	}

	var body struct {
		TGToken  string `json:"tg_token"`
		TGChatID string `json:"tg_chat_id"`
		IsActive bool   `json:"is_active"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	updateData := map[string]interface{}{
		"is_active": body.IsActive,
	}

	if body.TGToken != "" {
		updateData["tg_token"] = body.TGToken
	}
	if body.TGChatID != "" {
		updateData["tg_chat_id"] = body.TGChatID
	}

	if err := database.DB.Model(&config).Updates(updateData).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update telegram config"})
		return
	}

	c.JSON(http.StatusOK, config)
}

// handleDeleteTelegramConfig deletes a Telegram notification configuration
func handleDeleteTelegramConfig(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config ID is required"})
		return
	}

	if err := database.DB.Delete(&database.NotifyConfig{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete telegram config"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "telegram config deleted"})
}

// handleSaveTelegramSettings saves or updates Telegram bot token and chat ID
// This is a simplified endpoint that creates or updates the first active Telegram config
func handleSaveTelegramSettings(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	var body struct {
		Token  string `json:"token"`
		ChatID string `json:"chat_id"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if body.Token == "" || body.ChatID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token and chat_id are required"})
		return
	}

	// Check if a Telegram config already exists
	var existingConfig database.NotifyConfig
	err := database.DB.Where("is_active = ?", true).First(&existingConfig).Error

	if err != nil {
		// No active config exists, create a new one
		config := database.NotifyConfig{
			TGToken:  body.Token,
			TGChatID: body.ChatID,
			IsActive: true,
		}
		if err := database.DB.Create(&config).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create telegram config"})
			return
		}
		c.JSON(http.StatusCreated, gin.H{
			"message": "Telegram settings saved successfully",
			"config":  config,
		})
	} else {
		// Update existing config
		updateData := map[string]interface{}{
			"tg_token":   body.Token,
			"tg_chat_id": body.ChatID,
			"is_active":  true,
		}
		if err := database.DB.Model(&existingConfig).Updates(updateData).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update telegram config"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"message": "Telegram settings updated successfully",
			"config":  existingConfig,
		})
	}
}

// handleTestTelegramConnection tests the Telegram bot connection by sending a test message
func handleTestTelegramConnection(c *gin.Context) {
	if database.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not initialized"})
		return
	}

	id := c.Param("id")
	if id == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "config ID is required"})
		return
	}

	var config database.NotifyConfig
	if err := database.DB.First(&config, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "telegram config not found"})
		return
	}

	// Send test message
	testMessage := "Hello from ZenStack"
	if err := notify.SendTelegramMessage(config.TGToken, config.TGChatID, testMessage); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "failed to send test message",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Test message sent successfully",
		"chat_id": config.TGChatID,
	})
}

// sendTelegram sends a notification message to Telegram using configured bot token and chat ID.
// It retrieves the configuration from the database and handles network timeouts appropriately.
// This is a legacy function kept for backward compatibility.
func sendTelegram(message string) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	var config database.TelegramConfig
	if err := database.DB.Where("enabled = ?", true).First(&config).Error; err != nil {
		// No Telegram config found or disabled - not an error, just skip notification
		log.Printf("Telegram notification skipped: %v", err)
		return nil
	}

	if config.BotToken == "" || config.ChatID == "" {
		log.Printf("Telegram notification skipped: bot token or chat ID not configured")
		return nil
	}

	// Create HTTP client with timeout for Japan-to-Global requests
	client := &http.Client{
		Timeout: 15 * time.Second, // Important: timeout for network requests
	}

	// Telegram Bot API endpoint
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.BotToken)

	// Prepare request payload
	payload := map[string]string{
		"chat_id": config.ChatID,
		"text":     message,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Telegram payload: %w", err)
	}

	// Send request with timeout handling
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create Telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Network timeout or connection error
		log.Printf("Telegram notification failed (network error): %v", err)
		return fmt.Errorf("telegram network error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Telegram notification failed with status %d", resp.StatusCode)
		return fmt.Errorf("telegram API returned status %d", resp.StatusCode)
	}

	log.Printf("Telegram notification sent successfully")
	return nil
}

// startSSLMonitoring starts a background goroutine that periodically scans SSL certificates
// for all monitored domains using a non-blocking time.Ticker.
func startSSLMonitoring() {
	ticker := time.NewTicker(1 * time.Hour) // Check every hour
	defer ticker.Stop()

	log.Println("SSL monitoring goroutine started")

	// Run initial scan immediately
	go performSSLScan()

	// Periodic scans
	for range ticker.C {
		go performSSLScan()
	}
}

// performSSLScan scans all monitored domains for SSL certificate expiry.
func performSSLScan() {
	if database.DB == nil {
		return
	}

	var domains []database.MonitoredDomain
	if err := database.DB.Find(&domains).Error; err != nil {
		log.Printf("Failed to load monitored domains for SSL scan: %v", err)
		return
	}

	for _, monitoredDomain := range domains {
		result := domain.CheckCertificate(monitoredDomain.DomainName)
		
		// Update domain record with SSL expiry information
		updates := map[string]interface{}{
			"ssl_expiry":      result.ExpiryDate,
			"last_expiry_date": result.ExpiryDate,
			"status":          getStatus(result),
		}

		if err := database.DB.Model(&monitoredDomain).Updates(updates).Error; err != nil {
			log.Printf("Failed to update SSL expiry for domain %s: %v", monitoredDomain.DomainName, err)
			continue
		}

		// Send notification if certificate is critical or expired
		if result.DaysRemaining < criticalThreshold || result.Status == "Expired" {
			message := fmt.Sprintf("⚠️ SSL Alert: %s - %s (Days remaining: %d)",
				monitoredDomain.DomainName, result.Status, result.DaysRemaining)
			if err := sendTelegram(message); err != nil {
				log.Printf("Failed to send Telegram notification: %v", err)
			}
		}
	}
}

// startHTTPHealthChecks starts a background goroutine that periodically performs HTTP health checks
// for all monitored domains using a non-blocking time.Ticker.
func startHTTPHealthChecks() {
	ticker := time.NewTicker(5 * time.Minute) // Check every 5 minutes
	defer ticker.Stop()

	log.Println("HTTP health check goroutine started")

	// Run initial check immediately
	go performHTTPHealthChecks()

	// Periodic checks
	for range ticker.C {
		go performHTTPHealthChecks()
	}
}

// performHTTPHealthChecks performs HTTP health checks for all monitored domains.
func performHTTPHealthChecks() {
	if database.DB == nil {
		return
	}

	var domains []database.MonitoredDomain
	if err := database.DB.Find(&domains).Error; err != nil {
		log.Printf("Failed to load monitored domains for health check: %v", err)
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second, // Timeout for health checks
	}

	for _, monitoredDomain := range domains {
		// Try HTTPS first, then HTTP
		urls := []string{
			fmt.Sprintf("https://%s", monitoredDomain.DomainName),
			fmt.Sprintf("http://%s", monitoredDomain.DomainName),
		}

		var isLive bool
		var statusCode int

		for _, urlStr := range urls {
			resp, err := client.Get(urlStr)
			if err == nil {
				resp.Body.Close()
				isLive = true
				statusCode = resp.StatusCode
				break
			}
		}

		// Update domain record
		updates := map[string]interface{}{
			"is_live":         isLive,
			"last_status_code": statusCode,
		}

		if err := database.DB.Model(&monitoredDomain).Updates(updates).Error; err != nil {
			log.Printf("Failed to update health status for domain %s: %v", monitoredDomain.DomainName, err)
			continue
		}

		// Send notification if domain goes down
		if !isLive {
			message := fmt.Sprintf("🔴 Domain Down: %s is not reachable", monitoredDomain.DomainName)
			if err := sendTelegram(message); err != nil {
				log.Printf("Failed to send Telegram notification: %v", err)
			}
		}
	}
}

