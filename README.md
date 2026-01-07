# 🚀 ZenStack

**ZenStack** is a lightweight Internal Developer Platform (IDP) designed for modern SRE and DevOps teams. It eliminates infrastructure complexity by providing self-service capabilities and automated asset management.



## ✨ Key Features

-   **🌐 Domain & SSL Management:** Automated discovery of domain assets across multiple cloud providers (Aliyun, AWS, Cloudflare). Includes real-time SSL certificate monitoring and expiration alerts.
-   **🏗️ Self-Service Infrastructure:** Provision cloud resources (RDS, Redis, S3) using simple declarative YAML, powered by **Crossplane**.
-   **✨ Golden Paths (Scaffolding):** Spin up production-ready microservices in seconds with pre-configured CI/CD, monitoring, and security best practices.
-   **🤖 AI-Powered Ops:** Built-in LLM integration to diagnose deployment failures and provide root-cause analysis from logs.

## 🛠 技术栈 (Tech Stack)

-   **Backend:** Go 1.25+ (High-performance core engine)
-   **Portal:** Backstage (React/TypeScript)
-   **Orchestration:** Crossplane & Kubernetes
-   **Database:** PostgreSQL
-   **Observability:** OpenTelemetry & Prometheus integration

## 📂 Project Structure

```text
.
├── cmd/server          # Main API server and engine
├── pkg/providers       # Cloud provider implementations
│   ├── domain          # Domain discovery & SSL logic
│   └── infra           # Crossplane resource abstractions
├── ui/                 # Frontend portal (Backstage plugins)
├── templates/          # Service scaffolding templates
└── deploy/             # Kubernetes Helm charts & Docker Compose

## 🚦 Quick Start

### Prerequisites
- **Docker & Docker Compose**
- **Go 1.25+** (for local development)
- **A Kubernetes cluster** (optional, required for Infrastructure features)

### Run Locally

```bash
# 1. Clone the repository
git clone [https://github.com/harveywai/zenstack.git](https://github.com/harveywai/zenstack.git)
cd zenstack

# 2. Start the platform services (PostgreSQL, Engine, UI)
docker-compose up -d

# 3. Access the dashboard
# Open your browser and navigate to http://localhost:3000

