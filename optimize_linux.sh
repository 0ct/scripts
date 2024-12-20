#!/bin/bash

# 自动化Linux性能优化脚本  
# 支持系统：CentOS 7、Debian 11/12、Ubuntu 20.04/22.04/24.04  

# 添加日志功能
LOGFILE="/var/log/system_optimize.log"
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# 检查root权限
check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_message "Error: This script must be run as root"
        exit 1
    fi
}

# 检查必要命令
check_dependencies() {
    local deps=("ethtool" "sysctl" "sed" "awk" "grep")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            log_message "Error: Required command '$cmd' not found"
            exit 1
        fi
    done
}

# 备份配置文件
backup_configs() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/root/system_config_backup_${timestamp}"
    mkdir -p "$backup_dir"
    
    cp /etc/sysctl.conf "${backup_dir}/sysctl.conf.bak"
    cp /etc/security/limits.conf "${backup_dir}/limits.conf.bak"
    cp /etc/profile "${backup_dir}/profile.bak"
    
    log_message "Configuration files backed up to ${backup_dir}"
}

# 验证参数合法性
validate_params() {
    local value=$1
    local min=$2
    local max=$3
    local param_name=$4

    if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
        log_message "Warning: Invalid value for ${param_name}: ${value}. Using default value."
        return 1
    fi
    return 0
}

# 增强系统版本检测
detect_os() {
    # 添加更详细的版本检测
    if [ -f /etc/os-release ]; then
        OS=$(awk -F= '/^NAME/{print $2}' /etc/os-release | tr -d '"' | tr -d "'" | tr '[:upper:]' '[:lower:]' | awk '{print $1}')
        VERSION=$(lsb_release -r | awk '{print $2}')
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
        VERSION=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
    elif [ -f /etc/debian_version ]; then
        OS="debian"
        VERSION=$(cat /etc/debian_version | cut -d'.' -f1)
    else
        log_message "Error: Unsupported operating system"
        exit 1
    fi

    # 验证支持的系统版本
    case $OS in
        centos)
            if [ "$VERSION" -ne 7 ]; then
                log_message "Warning: Only CentOS 7 is fully supported"
            fi
            ;;
        debian)
            VERSION_NUM=$(echo "$VERSION" | grep -oE '^[0-9]+' || echo "0")
            if ! [[ "$VERSION_NUM" =~ ^[0-9]+$ ]] || [ "$VERSION_NUM" -lt 11 ] || [ "$VERSION_NUM" -gt 12 ]; then
                log_message "Warning: Only Debian 11/12 are fully supported"
            fi
            ;;
        ubuntu)
            
            if [[ ! "$VERSION" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
                log_message "Warning: Only Ubuntu 20.04/22.04/24.04 are fully supported"
            fi
            ;;
        *)
            log_message "Error: Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# 增强内核特性检查
check_kernel_features() {
    local kernel_version=$(uname -r)
    log_message "Detected kernel version: $kernel_version"

    # 检查必需的内核模块
    local required_modules=("tcp_bbr" "overlay" "br_netfilter")
    for module in "${required_modules[@]}"; do
        if ! lsmod | grep -q "^$module" && ! modprobe $module 2>/dev/null; then
            log_message "Warning: Required kernel module $module not available"
        fi
    done

    # 检查文件系统特性
    if ! grep -q "overlay" /proc/filesystems; then
        log_message "Warning: OverlayFS not supported by kernel"
    fi

    # 检查网络特性
    if [ ! -f /proc/sys/net/ipv4/tcp_available_congestion_control ]; then
        log_message "Warning: TCP congestion control not configurable"
    fi
}

# 根据内存计算共享内存参数 (shmmax and shmall)  
calculate_shared_memory_params() {  
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}') # 单位为 kB  
    SHMMAX=$((MEM_TOTAL * 1024 * 8 / 10)) # 80% 的内存大小，单位 bytes  
    SHMALL=$((SHMMAX / 4096))             # 页大小为 4KB  
}  

# 获取 CPU 核心数
get_cpu_cores() {
    CPU_CORES=$(nproc)
}

# 获取内存大小
get_memory_size() {
    MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}') # 单位为 kB
}

# 更新 sysctl.conf 文件
update_sysctl_conf() {
    declare -n config_params=$1
    for key in "${!config_params[@]}"; do
        sed -i "/${key}/d" /etc/sysctl.conf
        echo "${key} = ${config_params[$key]}" >> /etc/sysctl.conf
    done
}

# 合并配置系统核心参数、TCP 优化和启用IP转发的函数
configure_sysctl_and_tcp() {
    calculate_shared_memory_params
    get_cpu_cores
    get_memory_size

    # 验证内存参数
    local min_mem=$((1024 * 1024)) # 1GB
    local max_mem=$((1024 * 1024 * 1024)) # 1TB
    if ! validate_params "$MEM_TOTAL" "$min_mem" "$max_mem" "memory_size"; then
        MEM_TOTAL=$((16 * 1024 * 1024)) # 默认16GB
        MIN_MEM=$((TOTAL_MEM / 4))
        DEFAULT_MEM=$((TOTAL_MEM * 3 / 4))
        MAX_MEM=$((TOTAL_MEM * 7 / 8))
    fi

    # 添加错误处理
    local error_count=0

    echo "Calculated SHMMAX: $SHMMAX"
    echo "Calculated SHMALL: $SHMALL"
    echo "Detected CPU cores: $CPU_CORES"

    # 定义要删除和设置的参数
    declare -A params=( 
        # Base file-max value
        ["fs.file-max"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo $((CPU_CORES * 131072))
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo $((CPU_CORES * 98304))
            elif [ "$CPU_CORES" -ge 16 ] && [ "$MEM_TOTAL" -ge 16777216 ]; then
            echo $((CPU_CORES * 65536))
            else
            echo "2097152"
            fi
        )"
        ["fs.nr_open"]="$(
            if [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "2097152"
            elif [ "$CPU_CORES" -ge 16 ] && [ "$MEM_TOTAL" -ge 16777216 ]; then
            echo "1572864"
            else
            echo "1048576"
            fi
        )"
        ["kernel.shmmax"]="$SHMMAX"
        ["kernel.shmall"]="$SHMALL"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_fin_timeout"]="15"
        ["net.ipv4.tcp_tw_reuse"]="1"
        ["net.ipv4.tcp_keepalive_time"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "600"
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "1200"
            else
            echo "7200"
            fi
        )"
        ["net.ipv4.tcp_max_syn_backlog"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "65536"
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "32768"
            else
            echo "8192"
            fi
        )"
        ["net.ipv4.tcp_max_orphans"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "6553600"
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "4915200"
            else
            echo "3276800"
            fi
        )"
        ["vm.dirty_background_ratio"]="5"
        ["vm.dirty_ratio"]="10"
        ["net.ipv4.ip_local_port_range"]="1024 65535"
        ["net.ipv4.tcp_no_metrics_save"]="1"
        ["net.ipv4.tcp_ecn"]="0"
        ["net.ipv4.tcp_frto"]="0"
        ["net.ipv4.tcp_mtu_probing"]="0"
        ["net.ipv4.tcp_rfc1337"]="1"
        ["net.ipv4.tcp_sack"]="1"
        ["net.ipv4.tcp_fack"]="1"
        ["net.ipv4.tcp_window_scaling"]="1"
        ["net.core.default_qdisc"]="fq"
        ["net.ipv4.tcp_congestion_control"]="bbr"
        ["net.core.rmem_default"]="8388608"
        ["net.core.wmem_default"]="8388608"
        ["net.core.rmem_max"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "134217728"  # 128MB
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "67108864"   # 64MB
            else
            echo "33554432"   # 32MB
            fi
        )"
        ["net.core.wmem_max"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "134217728"  # 128MB
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "67108864"   # 64MB
            else
            echo "33554432"   # 32MB
            fi
        )"
        ["net.ipv4.tcp_rmem"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "4096 131072 134217728"
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "4096 87380 67108864"
            else
            echo "4096 87380 33554432"
            fi
        )"
        ["net.ipv4.tcp_wmem"]="$(
            if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
            echo "4096 32768 134217728"
            elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
            echo "4096 32768 67108864"
            else
            echo "4096 16384 33554432"
            fi
        )"
        ["net.ipv4.tcp_mem"]="$(
            if [ "$MEM_TOTAL" -ge 67108864 ]; then # >= 64GB
                echo "8388608 12582912 16777216"
            elif [ "$MEM_TOTAL" -ge 33554432 ]; then # >= 32GB
                echo "4194304 6291456 8388608"
            elif [ "$MEM_TOTAL" -ge 16777216 ]; then # >= 16GB
                echo "1048576 4194304 6291456"
            else
                echo "786432 1048576 1572864" # 默认值
            fi
        )"
        ["net.ipv4.ip_forward"]="1"
        ["net.ipv4.conf.all.forwarding"]="1"
        ["net.ipv4.conf.default.forwarding"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["net.ipv4.conf.default.accept_source_route"]="0"
        ["kernel.core_uses_pid"]="1"
        ["kernel.msgmnb"]="65536"
        ["kernel.msgmax"]="65536"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.tcp_max_tw_buckets"]="262144"
        ["net.ipv4.tcp_timestamps"]="1"
        ["net.ipv4.tcp_slow_start_after_idle"]="0"
        ["net.ipv4.tcp_early_retrans"]="1"
        ["net.ipv4.tcp_recovery"]="1"
        ["net.ipv4.tcp_retries2"]="8"
        ["net.ipv4.tcp_synack_retries"]="3"
        ["net.ipv4.tcp_syn_retries"]="3"
        ["kernel.panic"]="10"
        ["kernel.panic_on_oops"]="1"
        ["vm.swappiness"]="10"
        # NUMA 系统优化参数
        ["vm.zone_reclaim_mode"]="0"
        ["kernel.numa_balancing"]="0"
        ["vm.numa_stat"]="0"
        ["vm.numa_zonelist_order"]="Node"
        
        # IO相关优化参数
        ["vm.dirty_background_bytes"]="67108864"
        ["vm.dirty_bytes"]="134217728"
        ["vm.page-cluster"]="0"
        ["vm.dirty_expire_centisecs"]="3000"
        ["vm.dirty_writeback_centisecs"]="1000"
        
        # 容器环境优化参数
        ["kernel.keys.root_maxkeys"]="1000000"
        ["kernel.keys.maxkeys"]="1000000"
        ["fs.inotify.max_user_instances"]="8192"
        ["fs.inotify.max_user_watches"]="524288"
        ["kernel.pid_max"]="4194304"
    )

    # 根据 CPU 核心数和内存大小调整参数
    # Adjust network parameters based on CPU cores and memory
    if [ "$CPU_CORES" -le 24 ]; then
        params["net.core.somaxconn"]="8192"
        params["net.core.netdev_max_backlog"]="32768"
    elif [ "$CPU_CORES" -le 31 ]; then
        params["net.core.somaxconn"]="16384"
        params["net.core.netdev_max_backlog"]="65536"
    elif [ "$CPU_CORES" -le 39 ]; then
        params["net.core.somaxconn"]="32768"
        params["net.core.netdev_max_backlog"]="131072" 
    elif [ "$CPU_CORES" -le 47 ]; then
        params["net.core.somaxconn"]="65536"
        params["net.core.netdev_max_backlog"]="262144"
    elif [ "$CPU_CORES" -le 103 ]; then
        params["net.core.somaxconn"]="131072"
        params["net.core.netdev_max_backlog"]="524288"
    else
        params["net.core.somaxconn"]="262144"
        params["net.core.netdev_max_backlog"]="1048576"
    fi

    # Adjust tcp_max_tw_buckets based on memory size
    if [ "$MEM_TOTAL" -ge 33554432 ]; then # >= 32GB
        params["net.ipv4.tcp_max_tw_buckets"]="1048576"
    elif [ "$MEM_TOTAL" -ge 16777216 ]; then # >= 16GB
        params["net.ipv4.tcp_max_tw_buckets"]="524288"
    elif [ "$MEM_TOTAL" -ge 8388608 ]; then # >= 8GB
        params["net.ipv4.tcp_max_tw_buckets"]="262144"
    fi

    # 清理旧配置并写入新配置
    update_sysctl_conf params

    # 应用配置并检查错误
    if ! sysctl -p; then
        log_message "Error: Failed to apply sysctl settings"
        ((error_count++))
    fi

    if ! sysctl --system; then
        log_message "Error: Failed to apply system settings"
        ((error_count++))
    fi

    if [ $error_count -gt 0 ]; then
        log_message "Warning: Some settings failed to apply"
    fi

    echo "System core parameters, TCP optimization, and IP forwarding configuration completed."
}

# 配置系统文件句柄和进程数  
configure_limits() {  
    get_cpu_cores
    get_memory_size

    # 定义默认参数
    declare -A params=( 
        ["* soft nofile"]="1048576"
        ["* hard nofile"]="1048576"
        ["* soft nproc"]="655350"
        ["* hard nproc"]="655350"
        ["root soft nofile"]="1048576"
        ["root hard nofile"]="1048576"
        ["root soft nproc"]="655350"
        ["root hard nproc"]="655350"
    )

    # 根据 CPU 核心数和内存大小调整参数
    if [ "$CPU_CORES" -ge 48 ] && [ "$MEM_TOTAL" -ge 67108864 ]; then
        params["* soft nofile"]="6291456"
        params["* hard nofile"]="6291456"
        params["root soft nofile"]="6291456"
        params["root hard nofile"]="6291456"
    elif [ "$CPU_CORES" -ge 32 ] && [ "$MEM_TOTAL" -ge 33554432 ]; then
        params["* soft nofile"]="3145728"
        params["* hard nofile"]="3145728"
        params["root soft nofile"]="3145728"
        params["root hard nofile"]="3145728"
    elif [ "$CPU_CORES" -ge 16 ] && [ "$MEM_TOTAL" -ge 16777216 ]; then
        params["* soft nofile"]="1572864"
        params["* hard nofile"]="1572864"
        params["root soft nofile"]="1572864"
        params["root hard nofile"]="1572864"
    fi

    # 清理旧配置并写入新配置
    for key in "${!params[@]}"; do
        sed -i "/${key}/d" /etc/security/limits.conf
        echo "${key} ${params[$key]}" >> /etc/security/limits.conf
    done 

    grep -E -q "^\s*ulimit -HSn\s+\w+.*$" /etc/profile && \
        sed -ri "s/^\s*ulimit -HSn\s+\w+.*$/ulimit -HSn ${params["* soft nofile"]}/" /etc/profile || \
        echo "ulimit -HSn ${params["* soft nofile"]}" >> /etc/profile  

    grep -E -q "^\s*ulimit -HSu\s+\w+.*$" /etc/profile && \
        sed -ri "s/^\s*ulimit -HSu\s+\w+.*$/ulimit -HSu ${params["* soft nproc"]}/" /etc/profile || \
        echo "ulimit -HSu ${params["* soft nproc"]}" >> /etc/profile  
}  

# 优化网卡参数 (if needed, use ethtool)  
optimize_network() {  
    if command -v ethtool > /dev/null; then  
        NIC=$(ip -o -4 route show to default | awk '{print $5}')  

        if ethtool -g "$NIC" &>/dev/null; then  
            ethtool -G "$NIC" rx 4096 tx 4096 || echo "ethtool: failed to optimize NIC queue buffer, it might not be supported"  
        else  
            echo "NIC $NIC does not support RX/TX queue adjustment, skipping optimization."  
        fi  
    else  
        echo "ethtool command not available, skipping network optimization."  
    fi  
}  

# 检查内核版本 (remove deprecated parameters)  
check_kernel_version() {  
    KERNEL_MAJOR=$(uname -r | cut -d'.' -f1)
    KERNEL_MINOR=$(uname -r | cut -d'.' -f2)
    
    # 检查内核版本 >= 4.12 (移除已弃用的tcp_tw_recycle)
    if [[ "$KERNEL_MAJOR" -gt 4 || ("$KERNEL_MAJOR" -eq 4 && "$KERNEL_MINOR" -ge 12) ]]; then  
        echo "Detected kernel version >= 4.12, removing deprecated parameters..."  
        sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
    fi

    # 检查内核版本 >= 3.15 (TCP_FASTOPEN支持)
    if [[ "$KERNEL_MAJOR" -gt 3 || ("$KERNEL_MAJOR" -eq 3 && "$KERNEL_MINOR" -ge 15) ]]; then
        sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
        echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf
    fi

    # 检查内核版本 >= 4.9 (BBR支持)
    if [[ "$KERNEL_MAJOR" -gt 4 || ("$KERNEL_MAJOR" -eq 4 && "$KERNEL_MINOR" -ge 9) ]]; then
        if ! grep -q "fq" /proc/sys/net/core/default_qdisc 2>/dev/null || \
           ! grep -q "bbr" /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
            log_message "Warning: FQ qdisc or BBR congestion control not supported, removing related settings"
            sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
            sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        fi
    else
        # 对于较老的内核版本，移除BBR相关设置
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    fi

    # 检查内核版本 >= 5.0 (TCP_TW_REUSE默认启用)
    if [[ "$KERNEL_MAJOR" -ge 5 ]]; then
        log_message "Kernel version >= 5.0, tcp_tw_reuse is enabled by default"
        sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
    fi
}

# 优化发行版特定配置
os_specific_config() {
    log_message "Applying OS-specific optimizations for $OS $VERSION"
    
    case $OS in
        centos)
            if [ "$VERSION" -eq 7 ]; then
                # CentOS 7 特定优化
                yum install -y epel-release
                yum install -y irqbalance tuned
                systemctl enable irqbalance && systemctl start irqbalance
                tuned-adm profile throughput-performance
                
                # 禁用不必要的服务
                local services=("firewalld" "NetworkManager")
                for service in "${services[@]}"; do
                    if systemctl is-active $service >/dev/null 2>&1; then
                        systemctl stop $service
                        systemctl disable $service
                        log_message "Disabled service: $service"
                    fi
                done
            fi
            ;;
        debian|ubuntu)
            # Debian/Ubuntu 通用优化
            apt-get update
            apt-get install -y irqbalance tuned
            systemctl enable irqbalance && systemctl start irqbalance
            
            if [ "$OS" = "ubuntu" ] && [[ "$VERSION" =~ ^(20\.04|22\.04|24\.04)$ ]]; then
                # Ubuntu 特定优化
                tuned-adm profile throughput-performance
                
                # 检查和配置 Netplan
                if [ -d /etc/netplan ]; then
                    local netplan_file="/etc/netplan/99-custom-net.yaml"
                    if [ ! -f "$netplan_file" ]; then
                        cat > "$netplan_file" <<EOF
network:
  version: 2
  renderer: networkd
  ethernets:
    all:
      match:
        name: en*
      optional: true
      mtu: 9000
EOF
                        netplan apply
                        log_message "Applied network optimizations via Netplan"
                    fi
                fi
            fi
            ;;
    esac
}

# 验证和调整系统参数
validate_system_params() {
    # 验证内存参数
    local total_mem=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
    local page_size=$(getconf PAGE_SIZE)
    local cpu_cores=$(nproc)
    
    # 调整共享内存限制
    local shmmax=$((total_mem * 1024 * 8 / 10))
    local shmall=$((shmmax / page_size))
    
    # 验证值是否在合理范围内
    if [ "$shmmax" -gt "$(( 128 * 1024 * 1024 * 1024 ))" ]; then
        shmmax="$(( 128 * 1024 * 1024 * 1024 ))"
        log_message "Warning: Adjusted shmmax to maximum recommended value"
    fi

    # 返回验证后的参数
    echo "shmmax=$shmmax shmall=$shmall"
}

# 添加回滚功能
rollback_changes() {
    local backup_dir=$1
    if [ -f "${backup_dir}/sysctl.conf.bak" ]; then
        cp "${backup_dir}/sysctl.conf.bak" /etc/sysctl.conf
    fi
    if [ -f "${backup_dir}/limits.conf.bak" ]; then
        cp "${backup_dir}/limits.conf.bak" /etc/security/limits.conf
    fi
    if [ -f "${backup_dir}/profile.bak" ]; then
        cp "${backup_dir}/profile.bak" /etc/profile
    fi
    sysctl -p
    log_message "System configuration rolled back to previous state"
}

# NUMA系统优化
optimize_numa() {
    if [ -d "/sys/devices/system/node" ] && [ $(ls -d /sys/devices/system/node/node* 2>/dev/null | wc -l) -gt 1 ]; then
        log_message "NUMA system detected, applying NUMA optimizations..."
        
        # 设置CPU亲和性
        for pid in $(ps -eo pid,comm,psr | grep -E '(nginx|docker|containerd)' | awk '{print $1}'); do
            if [ -d "/proc/$pid" ]; then
                taskset -pc 0-$((CPU_CORES-1)) $pid >/dev/null 2>&1
            fi
        done

        # 安装并配置numad
        case $OS in
            centos)
                yum install -y numad numactl
                ;;
            debian|ubuntu)
                apt-get install -y numad numactl
                ;;
        esac

        systemctl enable numad
        systemctl start numad

        # 设置NUMA内存交错模式
        if command -v numactl >/dev/null; then
            echo "interleave=all" > /etc/numad.conf
        fi
    else
        log_message "No NUMA system detected, skipping NUMA optimizations"
    fi
}

# IO调度器优化
optimize_io_scheduler() {
    log_message "Configuring IO scheduler..."
    
    # 获取所有块设备
    local devices=$(lsblk -d -o name | tail -n +2)
    
    for device in $devices; do
        if [ -f "/sys/block/$device/queue/scheduler" ]; then
            # 检查设备类型
            if [[ $(cat /sys/block/$device/queue/rotational) -eq 0 ]]; then
                # SSD设备使用none或mq-deadline
                echo "none" > "/sys/block/$device/queue/scheduler" 2>/dev/null || \
                echo "mq-deadline" > "/sys/block/$device/queue/scheduler"
                
                # 优化SSD参数
                echo "0" > "/sys/block/$device/queue/add_random" 2>/dev/null
                echo "256" > "/sys/block/$device/queue/nr_requests" 2>/dev/null
            else
                # HDD设备使用bfq
                echo "bfq" > "/sys/block/$device/queue/scheduler"
                
                # 优化HDD参数
                echo "128" > "/sys/block/$device/queue/nr_requests" 2>/dev/null
                echo "1" > "/sys/block/$device/queue/add_random" 2>/dev/null
            fi
            
            # 通用优化参数
            echo "512" > "/sys/block/$device/queue/read_ahead_kb"
            echo "2" > "/sys/block/$device/queue/rq_affinity"
        fi
    done
}

# 容器环境优化
optimize_container_env() {
    log_message "Applying container-specific optimizations..."
    
    # 检查是否为容器环境
    if [ -f "/.dockerenv" ] || [ -f "/run/.containerenv" ] || systemctl status docker.service >/dev/null 2>&1; then
        # 优化容器运行时参数
        if systemctl status docker.service >/dev/null 2>&1; then
            mkdir -p /etc/docker
            cat > /etc/docker/daemon.json <<EOF
{
    "default-ulimits": {
        "nofile": {
            "Name": "nofile",
            "Hard": 655360,
            "Soft": 655360
        }
    },
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "max-concurrent-downloads": 10,
    "max-concurrent-uploads": 10,
    "storage-driver": "overlay2",
    "storage-opts": ["overlay2.override_kernel_check=true"],
    "exec-opts": ["native.cgroupdriver=systemd"],
    "registry-mirrors": ["https://registry.docker-cn.com"],
    "dns": ["8.8.8.8", "8.8.4.4"]
}
EOF
            systemctl restart docker
        fi

        # 配置containerd（如果存在）
        if command -v containerd >/dev/null; then
            mkdir -p /etc/containerd
            containerd config default > /etc/containerd/config.toml
            sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
            systemctl restart containerd
        fi

        # 优化内核参数
        cat >> /etc/sysctl.conf <<EOF
# Container specific settings
kernel.keys.root_maxkeys = 1000000
kernel.keys.maxkeys = 1000000
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 524288
kernel.pid_max = 4194304
EOF
    fi
}

# Main run logic  
main() {  
    log_message "Starting system optimization..."
    check_root
    check_dependencies
    backup_configs
    
    # 使用trap捕获错误
    trap 'log_message "Error occurred. Rolling back changes..."; rollback_changes "/root/system_config_backup_$(date +%Y%m%d_%H%M%S)"; exit 1' ERR

    detect_os
    check_kernel_features
    
    # 验证系统参数
    local validated_params=$(validate_system_params)
    eval $validated_params
    
    configure_sysctl_and_tcp
    configure_limits
    check_kernel_version
    optimize_network
    os_specific_config
    optimize_numa
    optimize_io_scheduler
    optimize_container_env
    
    log_message "System optimization completed successfully!"
    log_message "System information summary:"
    log_message "OS: $OS $VERSION"
    log_message "Kernel: $(uname -r)"
    log_message "CPU cores: $(nproc)"
    log_message "Memory: $(awk '/MemTotal/ {printf "%.1fGB", $2/1024/1024}' /proc/meminfo)"
    log_message "Please restart the system to apply all changes."
}  

main "$@"
