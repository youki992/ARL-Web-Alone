#!/bin/bash

# ARL 完整一键安装脚本 (Linux/macOS)
# 支持 Ubuntu, CentOS, macOS 等系统

set -e

echo "========================================"
echo "ARL 完整一键安装脚本 (Linux/macOS)"
echo "========================================"
echo

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检测操作系统
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$NAME
            VER=$VERSION_ID
        elif type lsb_release >/dev/null 2>&1; then
            OS=$(lsb_release -si)
            VER=$(lsb_release -sr)
        else
            OS=$(uname -s)
            VER=$(uname -r)
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macOS"
        VER=$(sw_vers -productVersion)
    else
        OS="Unknown"
        VER="Unknown"
    fi
    log_info "检测到操作系统: $OS $VER"
}

# 检查是否为root用户
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "检测到root用户，建议使用普通用户运行"
        read -p "是否继续？(y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 检查Python环境
check_python() {
    log_info "[1/8] 检查Python环境..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
        PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
        PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
        
        if [[ $PYTHON_MAJOR -eq 3 && $PYTHON_MINOR -ge 6 ]]; then
            log_info "✓ Python $PYTHON_VERSION 已安装"
            PYTHON_CMD="python3"
        else
            log_error "Python版本过低，需要Python 3.6+"
            exit 1
        fi
    else
        log_error "未找到Python 3，请先安装Python 3.6+"
        exit 1
    fi
    
    # 检查pip3
    if command -v pip3 &> /dev/null; then
        log_info "✓ pip3 已安装"
        PIP_CMD="pip3"
    else
        log_error "未找到pip3，请安装pip3"
        exit 1
    fi
}

# 安装系统依赖
install_system_deps() {
    log_info "[2/6] 安装系统依赖..."
    
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        # Ubuntu/Debian 系统依赖
        sudo apt-get update
        
        # 检查Ubuntu版本，为22.04+和24.04+安装特定依赖
        if [[ "$OS" == *"Ubuntu"* ]]; then
            UBUNTU_VER=$(echo $VER | cut -d. -f1)
            if [[ $UBUNTU_VER -ge 22 ]]; then
                log_info "检测到Ubuntu $VER，安装开发库..."
                sudo apt-get install -y libssl-dev libffi-dev python3-dev build-essential
            fi
            if [[ $UBUNTU_VER -ge 24 ]]; then
                log_info "检测到Ubuntu 24.04+，尝试安装libssl1.1兼容库..."
                # 尝试安装libssl1.1兼容库
                wget -q http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb 2>/dev/null || true
                if [ -f libssl1.1_1.1.1f-1ubuntu2_amd64.deb ]; then
                    sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb 2>/dev/null || true
                    rm -f libssl1.1_1.1.1f-1ubuntu2_amd64.deb
                fi
            fi
        fi
        
    elif [[ "$OS" == *"CentOS"* ]] || [[ "$OS" == *"Red Hat"* ]] || [[ "$OS" == *"Fedora"* ]]; then
        # CentOS/RHEL/Fedora 系统依赖
        if command -v dnf &> /dev/null; then
            sudo dnf install -y gcc gcc-c++ openssl-devel libffi-devel python3-devel
        else
            sudo yum install -y gcc gcc-c++ openssl-devel libffi-devel python3-devel
        fi
        
    elif [[ "$OS" == "macOS" ]]; then
        # macOS 系统依赖
        if ! command -v brew &> /dev/null; then
            log_warn "未找到Homebrew，请先安装Homebrew"
            log_info "安装命令: /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        else
            brew install openssl libffi
        fi
    fi
}





# 设置Python虚拟环境
setup_venv() {
    log_info "[3/6] 设置Python虚拟环境..."
    
    if [ -d "venv" ]; then
        log_info "虚拟环境已存在，激活中..."
        source venv/bin/activate
    else
        log_info "创建Python虚拟环境..."
        $PYTHON_CMD -m venv venv
        source venv/bin/activate
        
        # 升级pip和setuptools
        if [[ "$PYTHON_VERSION" == "3.12"* ]]; then
            $PIP_CMD install --upgrade "pip<24.1" setuptools
        else
            $PIP_CMD install --upgrade pip setuptools
        fi
    fi
    
    log_info "✓ 虚拟环境设置完成"
}

# 安装Python依赖
install_python_deps() {
    log_info "[4/6] 安装Python依赖..."
    
    # 使用完整依赖列表或原始依赖列表
    if [ -f "requirements-complete.txt" ]; then
        log_info "使用完整依赖列表..."
        REQUIREMENTS_FILE="requirements-complete.txt"
    else
        log_info "使用原始依赖列表..."
        REQUIREMENTS_FILE="requirements.txt"
    fi
    
    # 尝试安装依赖
    if ! $PIP_CMD install -r $REQUIREMENTS_FILE; then
        log_warn "使用默认源安装失败，尝试使用国内镜像源..."
        $PIP_CMD install -r $REQUIREMENTS_FILE -i https://pypi.tuna.tsinghua.edu.cn/simple/ --trusted-host pypi.tuna.tsinghua.edu.cn
    fi
    
    log_info "✓ 主项目依赖安装完成"
}

# 安装ARL-NPoC依赖
install_npoc_deps() {
    log_info "[5/6] 安装ARL-NPoC依赖..."
    
    # 确保在虚拟环境中
    source venv/bin/activate
    
    if [ -d "ARL-NPoC/ARL-NPoC-master" ]; then
        cd ARL-NPoC/ARL-NPoC-master
        if [ -f "requirements.txt" ]; then
            log_info "安装ARL-NPoC依赖..."
            $PIP_CMD install -r requirements.txt
            log_info "✓ ARL-NPoC requirements.txt依赖安装完成"
        else
            log_warn "未找到ARL-NPoC/ARL-NPoC-master/requirements.txt文件"
        fi
        
        # 安装xing模块
        if [ -f "setup.py" ]; then
            log_info "安装xing模块..."
            $PIP_CMD install -e .
            log_info "✓ xing模块安装完成"
        else
            log_warn "未找到setup.py文件，无法安装xing模块"
        fi
        
        cd ../..
    elif [ -d "ARL-NPoC" ]; then
        # 兼容直接解压到ARL-NPoC目录的情况
        cd ARL-NPoC
        if [ -f "requirements.txt" ]; then
            log_info "安装ARL-NPoC依赖..."
            $PIP_CMD install -r requirements.txt
            log_info "✓ ARL-NPoC requirements.txt依赖安装完成"
        else
            log_warn "未找到ARL-NPoC/requirements.txt文件"
        fi
        
        # 安装xing模块
        if [ -f "setup.py" ]; then
            log_info "安装xing模块..."
            $PIP_CMD install -e .
            log_info "✓ xing模块安装完成"
        else
            log_warn "未找到setup.py文件，无法安装xing模块"
        fi
        
        cd ..
    else
        log_warn "未找到ARL-NPoC目录"
    fi
}

# 设置工具可执行权限
set_tools_permissions() {
    log_info "[6/7] 设置工具可执行权限..."
    
    # 检查app/tools目录是否存在
    if [ ! -d "app/tools" ]; then
        log_warn "app/tools 目录不存在，跳过权限设置"
        return
    fi
    
    # 为工具文件设置可执行权限
    local tools_dir="app/tools"
    local tools=("wih" "vscanPlus" "massdns" "phantomjs" "naabu")
    
    for tool in "${tools[@]}"; do
        if [ -f "$tools_dir/$tool" ]; then
            chmod +x "$tools_dir/$tool"
            log_info "✓ 已设置 $tool 可执行权限"
        elif [ -f "$tools_dir/$tool.exe" ]; then
            chmod +x "$tools_dir/$tool.exe"
            log_info "✓ 已设置 $tool.exe 可执行权限"
        else
            log_warn "工具文件 $tool 不存在，跳过"
        fi
    done
    
    # 设置整个tools目录的权限
    chmod -R 755 "$tools_dir" 2>/dev/null || true
    log_info "✓ 工具权限设置完成"
}

# 配置文件设置
setup_config() {
    log_info "[7/7] 设置配置文件..."
    
    if [ ! -f "app/config.yaml" ]; then
        if [ -f "app/config-docker.yaml" ]; then
            log_info "复制配置文件模板..."
            cp app/config-docker.yaml app/config.yaml
            log_info "✓ 配置文件创建完成，请根据需要修改 app/config.yaml"
        else
            log_warn "未找到配置文件模板"
        fi
    else
        log_info "✓ 配置文件已存在"
    fi
    
    # 设置执行权限
    chmod +x start_*.py 2>/dev/null || true
}

# 主函数
main() {
    detect_os
    check_root
    check_python
    install_system_deps
    setup_venv
    install_python_deps
    install_npoc_deps
    set_tools_permissions
    setup_config
    
    echo
    echo "========================================"
    echo "安装完成！"
    echo "========================================"
    echo
    echo "下一步操作："
    echo "1. 手动安装并启动MongoDB服务"
    echo "2. 手动安装并启动RabbitMQ服务"
    echo "3. 编辑 app/config.yaml 配置文件"
    echo "4. 激活虚拟环境: source venv/bin/activate"
    echo "5. 运行 python3 start_all.py 启动服务"
    echo
    echo "详细说明请参考 README-STANDALONE.md"
    echo
    echo "注意：MongoDB和RabbitMQ需要手动安装和配置"
    echo "注意：工具权限已自动设置，如有问题请手动执行: chmod +x app/tools/*"
    echo
}

# 运行主函数
main "$@"