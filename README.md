# 🚀 ZenStack

**ZenStack** 是一个为开发者设计的轻量级内部平台 (IDP)，旨在消除基础设施的复杂性。

### ✨ 核心功能
- **Domain Assets:** 自动化域名资产发现、SSL 证书监控与到期预警。
- **Self-Service Infra:** 基于 Crossplane 的声明式资源申请 (RDS, Redis, S3)。
- **Golden Paths:** 预设黄金路径，5秒钟生成符合规范的微服务代码。

### 🛠 技术栈
- **Backend:** Go 1.25+
- **Portal:** Backstage (React/TypeScript)
- **Engine:** Crossplane + Kubernetes
- **Database:** PostgreSQL

### 🚦 快速开始
```bash
docker-compose up -d
# 访问 http://localhost:3000
