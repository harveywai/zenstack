# 🚀 ZenStack

**ZenStack** is a lightweight Internal Developer Platform (IDP) designed for modern SRE and DevOps teams. It eliminates infrastructure complexity by providing self-service capabilities and automated asset management.



## ✨ Key Features

- **🌐 Domain & SSL Management:** Automated discovery of domain assets across Cloud providers. Includes real-time SSL certificate monitoring and expiration alerts.
- **🏗️ Self-Service Infrastructure:** Provision cloud resources (RDS, Redis, S3) using simple declarative YAML, powered by **Crossplane**.
- **✨ Golden Paths (Scaffolding):** Spin up production-ready microservices in seconds with pre-configured CI/CD and monitoring.
- **🤖 AI-Powered Ops:** Built-in LLM integration to diagnose deployment failures.

## 🛠 Tech Stack

- **Backend:** Go 1.25+
- **Portal:** Backstage (React/TypeScript)
- **Engine:** Crossplane & Kubernetes
- **Database:** PostgreSQL

## 🚦 Quick Start

### Prerequisites
- Docker & Docker Compose
- Go 1.25+

### Run Locally
```bash
# 1. Clone the repository
git clone [https://github.com/harveywai/zenstack.git](https://github.com/harveywai/zenstack.git)
cd zenstack

# 2. Start the platform
docker-compose up -d

# 3. Access the dashboard
# Open http://localhost:3000

🤝 Contributing
We welcome contributions! Please check our CONTRIBUTING.md.

📄 License
This project is licensed under the Apache License 2.0.

