# 1. 创建项目目录
mkdir zenstack && cd zenstack

# 2. 初始化本地 Git 仓库
git init -b main

# 3. 创建最小化的目录结构 (遵循 Go 与 Backstage 的混合架构)
mkdir -p cmd/server pkg/providers/domain pkg/providers/infra ui/plugins templates deploy/helm docs

# 4. 创建 README (这是你的“产品说明书”)
touch README.md CONTRIBUTING.md LICENSE

# 5. 使用 GitHub CLI 创建远程仓库并关联
# --public 设为公开，--description 增加描述
gh repo create zenstack --public --description "Next-gen Lightweight IDP: Infrastructure Self-service & Domain Asset Management" --source=. --remote=origin --push
