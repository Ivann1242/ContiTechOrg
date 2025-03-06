#!/bin/bash

# 部署配置
DEPLOY_DIR="/var/www/ContiTechOrg/CONTI-CN"
DOMAIN="3.22.241.231"
PM2_APP_NAME="conti-server"
REPO_URL="git@github.com:Ivann1242/ContiTechOrg.git"
BRANCH="main"

# 错误处理函数
handle_error() {
    echo "错误: $1"
    exit 1
}

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# 检查服务器状态函数
check_server() {
    local max_attempts=5
    local wait_time=3
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log "检查服务器状态 (尝试 $attempt/$max_attempts)..."
        if curl -s "http://$DOMAIN:3001/api/test-db" > /dev/null; then
            log "服务器响应正常"
            return 0
        else
            log "等待服务器启动... (${wait_time}s)"
            sleep $wait_time
            attempt=$((attempt + 1))
        fi
    done
    
    log "警告: 服务器未响应，请检查日志"
    pm2 logs $PM2_APP_NAME --lines 50
    return 1
}

log "开始部署 CONTI 网站..."

# 1. 检查是否已经在目标目录
if [ "$PWD" != "$DEPLOY_DIR" ]; then
    log "切换到部署目录..."
    cd $DEPLOY_DIR || handle_error "无法切换到目录 $DEPLOY_DIR"
fi

# 2. 拉取最新代码
log "从 GitHub 拉取最新代码..."
git fetch origin $BRANCH || handle_error "无法从GitHub拉取代码"
git checkout $BRANCH || handle_error "无法切换到 $BRANCH 分支"
git reset --hard origin/$BRANCH || handle_error "无法重置代码到最新状态"
git pull origin $BRANCH || handle_error "无法拉取最新代码"

# 3. 安装依赖
log "安装项目依赖..."
npm install || handle_error "npm install 失败"

# 4. 更新环境变量
log "更新环境变量..."
cat > .env << EOF || handle_error "无法创建 .env 文件"
DOMAIN=http://$DOMAIN
PORT=3001
NODE_ENV=production
EMAIL_USER=ContiTechOrg@gmail.com
EMAIL_PASS=gbrkmamctxmlhloq
JWT_SECRET=conti_2024_secure_jwt_key_8a7b6c5d4e3f2g1h
EOF

# 5. 确保权限配置
log "配置权限..."
sudo chmod 600 CTO.pem || handle_error "无法设置 CTO.pem 权限"
mkdir -p uploads || handle_error "无法创建 uploads 目录"
chmod 755 uploads || handle_error "无法设置 uploads 目录权限"

# 6. 清理和重启服务器
log "清理和重启服务器..."
# 停止现有进程
pm2 stop all 2>/dev/null || true
pm2 delete all 2>/dev/null || true

# 启动新进程
log "启动服务器..."
NODE_ENV=production pm2 start server.js --name $PM2_APP_NAME --update-env || handle_error "无法启动服务器"

# 保存 PM2 进程列表
log "保存进程配置..."
pm2 save --force || handle_error "无法保存 PM2 配置"

log "部署完成!"
log "网站可以通过 http://$DOMAIN:3001 访问"

# 显示PM2状态
pm2 status

# 检查服务器状态并显示日志
check_server || log "请手动检查服务器状态和日志" 