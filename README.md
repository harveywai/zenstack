🚀 ZenStack
ZenStack is a lightweight Internal Developer Platform (IDP) designed for modern SRE and DevOps teams. It eliminates infrastructure complexity by providing self-service capabilities and automated asset management.

✨ Key Features
🌐 Domain & SSL Management: Automated discovery of domain assets across multiple cloud providers. Includes real-time SSL certificate monitoring and expiration alerts.

🏗️ Self-Service Infrastructure: Provision cloud resources (RDS, Redis, S3) using simple declarative YAML, powered by Crossplane.

✨ Golden Paths (Scaffolding): Spin up production-ready microservices in seconds with pre-configured CI/CD, monitoring, and security best practices.

🤖 AI-Powered Ops: Built-in LLM integration to diagnose deployment failures and provide root-cause analysis from logs.

🛠 Tech Stack
Backend: Go 1.25+ (High-performance core engine)

Portal: Backstage (React/TypeScript)

Orchestration: Crossplane & Kubernetes

Database: PostgreSQL

Observability: OpenTelemetry & Prometheus integration

📂 Project Structure
Plaintext

.
├── cmd/server          # Main API server and engine
├── pkg/providers       # Cloud provider implementations (Aliyun, AWS, etc.)
│   ├── domain          # Domain discovery & SSL logic
│   └── infra           # Crossplane resource abstractions
├── ui/                 # Frontend portal (Backstage plugins)
├── templates/          # Service scaffolding templates
└── deploy/             # Kubernetes Helm charts & Docker Compose
🚦 Quick Start
Prerequisites
Docker & Docker Compose

A Kubernetes cluster (optional, for Infra features)

Run Locally
Bash

# Clone the repository
git clone https://github.com/YOUR_USERNAME/zenstack.git
cd zenstack

# Start the platform
docker-compose up -d

# Access the dashboard at http://localhost:3000
🤝 Contributing
We welcome contributions! Whether it's a new cloud provider, a bug fix, or a feature request, please check our CONTRIBUTING.md.

📄 License
This project is licensed under the Apache License 2.0 - see the LICENSE file for details.
