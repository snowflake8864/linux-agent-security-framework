# Linux Agent Security Framework

一个基于 eBPF 的 Linux 系统安全代理框架，提供网络端口转发、文件访问控制、进程监控和网络安全防护功能。

## 功能特性

- **远程端口转发**：TCP 端口流量转发到其他服务器
- **本地端口转发**：本机端口重定向到其他端口（127.0.0.1）
- **文件监控**：文件访问控制（读写删除等操作）
- **进程监控**：进程执行监控和控制
- **网络安全**：基于 XDP/TC 的高速网络数据包处理

## 系统要求

- Linux 内核 >= 5.8（支持 eBPF）
- Rust 1.70+
- clang/llvm
- libbpf 开发包

## 安装编译

### 1. 安装依赖
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential clang llvm libelf-dev libbpf-dev

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install clang llvm elfutils-libelf-devel libbpf-devel
```

### 2. 编译 eBPF 内核模块
```bash
cargo run -p xtask -- build-bpf
```

### 3. 编译用户态程序
```bash
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

## 使用方法

### 端口转发应用

1. 配置文件 `forward_config.json`：
```json
{
  "forward_rules": [
    {
      "listen_port": [1000, "2000-2010"],
      "target_host": "192.168.134.81",
      "target_port": 22,
      "allowed_sources": ["0.0.0.0/0"]
    }
  ]
}
```

2. 运行端口转发：
```bash
echo "your_password" | sudo -S ./target/x86_64-unknown-linux-musl/release/forward \
  --config forward_config.json \
  --bpf-obj bpf/forward.bpf.o \
  --interface enp2s0 \
  --cgroup /sys/fs/cgroup
```

### 统一安全代理

#### 远程端口转发配置
```json
{
  "network": {
    "enabled": true,
    "engine": "xdp",
    "interface": "enp2s0",
    "forward_rules": [
      {
        "listen_port": [1000],
        "target_host": "192.168.3.4", 
        "target_port": 22,
        "protocol": "tcp",
        "allowed_sources": ["0.0.0.0/0"]
      }
    ]
  }
}
```

#### 本地端口转发配置
```json
{
  "network": {
    "enabled": true,
    "engine": "xdp", 
    "interface": "enp2s0",
    "forward_rules": [],
    "local_forward_rules": [
      {
        "listen_port": [8080],
        "target_port": 80,
        "protocol": "tcp",
        "allowed_sources": ["0.0.0.0/0"]
      },
      {
        "listen_port": ["9000-9010"],
        "target_port": 3000,
        "protocol": "tcp",
        "allowed_sources": ["192.168.1.0/24"]
      }
    ]
  },
  "file_rules": [
    {
      "path_prefix": "/tmp/secret.txt",
      "operations": ["Read", "Write"],
      "action": "Deny"
    }
  ],
  "process_rules": [
    {
      "comm": "nc",
      "action": "Deny"
    }
  ]
}
```

2. 运行统一代理：
```bash
echo "your_password" | sudo -S ./target/x86_64-unknown-linux-musl/release/unified-agent \
  --config unified_config.json \
  --cgroup /sys/fs/cgroup
```

### Demo 应用

```bash
echo "your_password" | sudo -S ./target/release/demo config.json
```

## 配置说明

### 远程端口转发规则（forward_rules）
- `listen_port`: 监听端口（支持单个端口或端口范围）
- `target_host`: 目标主机 IP
- `target_port`: 目标端口
- `protocol`: 协议类型（tcp/udp）
- `allowed_sources`: 允许的源 IP（CIDR 格式）

### 本地端口转发规则（local_forward_rules）
- `listen_port`: 监听端口（支持单个端口或端口范围）
- `target_port`: 本机目标端口
- `protocol`: 协议类型（tcp/udp）
- `allowed_sources`: 允许的源 IP（CIDR 格式）

**注意**：本地转发不需要 `target_host`，流量直接重定向到本机的指定端口。

### 文件访问规则
- `path_prefix`: 文件路径前缀
- `operations`: 操作类型（Read/Write/Create/Delete）
- `action`: 动作（Allow/Deny）

### 进程控制规则
- `comm`: 进程名称
- `action`: 动作（Allow/Deny）
- `mode`: 模式（Monitor/Protect）

## 故障排查

1. **检查内核版本**：
```bash
uname -r
```

2. **查看 eBPF 程序状态**：
```bash
sudo bpftool prog list
```

3. **检查日志**：
```bash
sudo dmesg | grep -i ebpf
sudo journalctl -f
```

4. **权限问题**：
确保以 root 权限运行，或者配置适当的 sudo 规则。

5. **网络接口确认**：
```bash
ip addr show
```

## 项目结构

```
├── apps/                # 用户态应用
│   ├── forward/        # 端口转发
│   ├── unified-agent/  # 统一代理
│   └── demo/           # 演示程序
├── bpf/                # 编译好的 eBPF 对象文件
├── ebpf-common/        # 共享的 eBPF 定义
└── xtask/             # 构建任务
```

## 开发

### 添加新功能
1. 在 `ebpf-common` 中定义新的 eBPF 数据结构
2. 在对应的应用目录中实现用户态逻辑
3. 更新配置文件格式

### 调试 eBPF 程序
```bash
# 查看 eBPF 映射
sudo bpftool map list

# 查看程序日志
sudo bpftool prog dump xlated id <prog_id>
```

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request。

## 注意事项

- 需要 root 权限运行
- 生产环境请充分测试
- eBPF 程序可能影响系统性能，建议在测试环境验证
