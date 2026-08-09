# Keyben

[English](README.md) | 简体中文

**Keyben是一个由Rust编写的端到端加密的密钥管理工具。** 并采用单一的二进制文件，既能当服务端也能当客户端。加解密全部发生在你的机器上，服务器只存储密文。

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

> 拉取密文 → 本地解密 → 直接注入子进程环境变量。不生成 `.env` 文件

---

## 类型

|  |                                                                    |
| --- |--------------------------------------------------------------------|
| **形态** | 单个可执行文件，服务端与客户端二合一                               |
| **实现** | Rust                                                               |
| **存储** | SQLite 单文件                                                      |
| **加密** | 客户端 XChaCha20-Poly1305 + Argon2id + 信封加密                    |
| **传输** | HTTP(S) + Bearer Token，可选 TLS                                   |
| **平台** | Linux（glibc / musl）、macOS Apple Silicon、Windows x86_64 / ARM64 |
| **许可** | MIT                                                                |

## 定位

keyben在设计时主要针对自托管的个人项目和小团队. 它刻意做得很小：无需复杂的部署流程,单一二进制, 采用SQLite,并采用严格的加密保护你的密钥.让你不再担心.env和密钥被泄漏

### 工作原理

```text
密码 ──Argon2id(盐)──▶ enc_key ──解包──▶ 项目数据密钥 (DEK)
     │                                          │
     ▼                                          ▼
 明文 ──────── 客户端：XChaCha20-Poly1305 ──────┘
     │  Base64 密文 over HTTP(S) + Bearer Token
     ▼
 服务端：SQLite（盐、被包裹的 DEK、认证哈希、密文）
     │
     ▼
 客户端：下载密文，用 DEK 在本地解密
```

密钥编排:

```text
master_key  = Argon2id(password, project_salt, m=64MiB, t=3, p=4)
enc_key     = HKDF-SHA256(master_key, "keyben v1 kek")    # 包裹 DEK，仅客户端持有
auth_secret = HKDF-SHA256(master_key, "keyben v1 auth")   # 发给服务端做项目认证
```

两个子密钥做了域分离，所以服务端看到的 `auth_secret` 不泄露任何关于加密密钥的信息。


### Why keyben?
- 默认采用不信任服务器机制. 客户端使用XChaCha20-Poly1305 + Argon2id + 信封加密完成加解密。服务器仅存储被加密的密钥
- 采用zeroize保证密钥不会被core dump解密
- 采用auth_token保护api不被调用,并使用项目密码加解密密码以及调用认证
- 使用keyben run把解密后的值直接交给子进程,无需.env或额外文件
- 即使auth_token丢失,也无法获取密钥,只能离线爆破 Argon2id, 每次猜测要付 64 MiB 内存的代价,无需担心被爆破,但小心不要使用简单的密码

### 小心
- **不要采用弱密码。** Argon2id 和每项目独立的盐让每次猜测变贵、消除彩虹表和跨项目密钥复用，但短密码或常见密码照样会被爆破。请用长的随机密码。
- **保证服务的安全** 虽然数据库中的数据被加密, 一旦黑客攻击了你的服务器, 它可以删除、替换你的数据或拒绝返回密文。请自行备份与监控。
- **token泄漏** Keyben为了简单,没有设计用户、角色、权限分级、token 轮换或审计日志,如果token一旦泄漏,你的token将被黑客用于获取加密的密钥,即使黑客无法破解它,但黑客可以向你的服务端写入垃圾数据
- **使用tls加密、反向代理或在受信任的环境使用http** 如果采用http,容易被重放攻击或监听,仅限可信内网（例如 Tailscale）这样用或配置tls
- **优先采用交互式命令** `--value` / `--password` 会进入 shell 历史和进程列表，优先用交互式输入。
- **定期保存数据库和保存密码** 一旦数据库丢失或密码丢失,神仙也救不了你

---

## 安装

### 下载预编译二进制

从 [GitHub Releases](https://github.com/senseiod/keyben/releases) 下载对应平台的压缩包。

**Linux / macOS**

```bash
tar -xzf keyben-linux-x86_64.tar.gz
sudo install -m 0755 keyben-linux-x86_64/keyben /usr/local/bin/keyben
keyben --version
```

**Windows**（PowerShell）

```powershell
tar -xzf .\keyben-windows-x86_64.tar.gz
```

解压后把目录加入 `PATH`。所有平台的发布包都是 `.tar.gz`，Windows 包内含 `keyben.exe`。

可用的包名：

| 包名 | 目标平台 |
| --- | --- |
| `keyben-linux-x86_64` | Linux x86_64（glibc） |
| `keyben-linux-arm64` | Linux ARM64（glibc） |
| `keyben-linux-musl-x86_64` | Linux x86_64（musl，如 Alpine） |
| `keyben-linux-musl-arm64` | Linux ARM64（musl） |
| `keyben-macos-arm64` | macOS Apple Silicon |
| `keyben-windows-x86_64` | Windows x86_64 |
| `keyben-windows-arm64` | Windows ARM64 |

每个 Release 同时发布 `SHA256SUMS` 用于校验。

### 从源码构建

需要当前 stable Rust 工具链：

```bash
git clone https://github.com/senseiod/keyben.git
cd keyben
cargo build --locked --release
```

产物在 `target/release/keyben`。也可以直接安装：

```bash
cargo install --path . --locked
```

---

## 服务端

### 配置

创建 `config.toml`：

```toml
[server]

# 监听地址和端口
listen = "0.0.0.0:8000"

# SQLite 文件，父目录会自动创建
data = "keyben.db"

# HTTP API 认证 token（必填，不能为空）, 建议采用` openssl rand -hex 32 `生成 auth_token
auth_token = "replace-with-a-long-random-token"

# 两个都配置才启用 HTTPS, 只配一个会拒绝启动；都省略则使用 HTTP
# cert = "/etc/keyben/server.crt"
# key  = "/etc/keyben/server.key"
```

用工具生成 auth_token

```bash
openssl rand -hex 32
```

### 启动

```bash
#  采用--config 启动服务端
keyben --config config.toml

# 也支持使用-c
keyben -c config.toml

# 带日志的前台运行
RUST_LOG=keyben=info,tower_http=info keyben -c config.toml
```

启动后会打印 HTTP/HTTPS 地址和数据库路径，`Ctrl-C` 优雅退出。不要把 `--config` 和客户端子命令混用。
推荐使用systemd来启动服务

> **注意：** `tower_http=debug` 会把请求路径写进日志，其中包含变量名（但不含值）。生产环境建议保持 `info`。

### 健康检查

`/healthz` 和其他端点一样在 Bearer Token 之后 —— 未认证的人连"有哪些项目存在"都探测不到，因此监控探针也需要带上 token：

```bash
curl --fail -H "Authorization: Bearer ${KEYBEN_TOKEN}" http://127.0.0.1:8000/healthz
```

### 备份与恢复

数据库里是每项目的信封元数据（Argon2 盐、被包裹的 DEK、认证哈希）和加密后的值。**定期备份这个 SQLite 文件**

恢复不需要重新加密：还原 SQLite 文件、用兼容配置启动服务端、客户端继续用原来的项目密码即可。

> 密码不由 keyben 保存，也无法由服务端找回。密码丢失 = 被包裹的 DEK 无法解开 = 该项目所有密文永久不可读。

---

## 客户端

### 五分钟上手

```bash
# (可选) 使用环境变量配置, 对于CI等自动化部署非常好
export KEYBEN_SERVER="https://secrets.example.com"
export KEYBEN_TOKEN="服务端 config.toml 里的 auth_token"
export KEYBEN_PASSWORD="项目对应的密码"

# 1. 创建项目
keyben init --projectName myapp

# 2. 写入一个密钥
keyben secrets set --projectName myapp --env dev --name DB_URL --value 'postgres://user:pw@db.example.com/app' --password 123456
# 或
keyben secrets set --projectName myapp --env dev

# 3. 读取 一个密钥
keyben secrets get --projectName myapp --env dev --name DB_URL
# 或读取所有
keyben secrets get --projectName myapp --env dev

# 4. 将密钥传递给你的服务
keyben run --projectName myapp --env dev -- npm run dev

# 其他

# 在你的项目中创建一个.keyben.toml. 下次就无需输入--projectName --token --server
keyben config init 
```

### 命令一览

| 命令 | 作用 |
| --- | --- |
| `keyben init` | 在服务端创建项目并设置密码 |
| `keyben config init` | 生成项目本地的加密配置文件 `.keyben.toml` |
| `keyben secrets set` | 加密并写入一个变量 |
| `keyben secrets get` | 读取并解密一个变量，或整个环境 |
| `keyben secrets delete` | 删除一个变量 |
| `keyben password reset` | 更换项目密码（密文不动） |
| `keyben run -- <cmd>` | 注入解密后的环境变量并启动子进程 |

全局选项：`--server` / `--token` / `--password` / `--insecure`，分别对应环境变量 `KEYBEN_SERVER`、`KEYBEN_TOKEN`、`KEYBEN_PASSWORD`、`KEYBEN_INSECURE`。

### 项目本地配置

不想每次都导出环境变量或输入--projectName --token --server，可以在项目目录生成一个加密的 `.keyben.toml`：

```bash
keyben config init
```

省略的值会交互式询问。服务器地址和 token 用**项目密码**加密后写入 —— 只需要记一个密码。项目名保持明文，作为默认的项目标识。文件已存在时会先询问是否覆盖。

之后在该目录下运行任何命令，keyben 问一次项目密码，同时用它解密配置文件和解锁项目。取值优先级：

```text
命令行参数  >  KEYBEN_SERVER / KEYBEN_TOKEN  >  .keyben.toml
```

自动化场景用 `--password` 或 `KEYBEN_PASSWORD` 免交互。

> **这个文件里没有密钥材料。** 它用独立的 Argon2id 盐加密，密钥与项目主密钥无关；项目 DEK 始终包裹在服务端。破解这个文件的人得到的是 token 的可达范围，仍然解不开任何密钥。keyben 不会为它设置特殊的文件权限 —— 除非有意为之，否则不要提交进版本库。

### 管理密钥

**写入 / 覆盖**

```bash
keyben secrets set --projectName myapp --env dev \
  --name DB_URL --value 'postgres://user:pw@db.example.com/app'
```

值在本地加密后才发出。`--env` 只接受 `dev` 或 `prod`。

在交互式终端里 `--name` 和 `--value` 都可以省略，keyben 会提示输入变量名，并以不回显的方式读取值 —— **推荐用这种方式**，避免明文进入 shell 历史：

```bash
keyben secrets set --projectName myapp --env dev
```

**读取单个**

```bash
keyben secrets get --projectName myapp --env dev --name DB_URL
```

解密后的明文打印到标准输出。

**读取整个环境**

```bash
keyben secrets get --projectName myapp --env dev
```

按变量名排序，以 `KEY=VALUE` 的形式输出。含换行的值自然会跨多行。

**删除**

```bash
keyben secrets delete --projectName myapp --env dev --name DB_URL
```

### 运行子进程

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

`--` 之后的一切都是子命令及其参数。keyben 拉取并解密整个环境，启动子进程，并透传它的退出码。

子进程继承调用者的环境，加上解密出的密钥，**减去 keyben 自己的凭据** —— `KEYBEN_TOKEN`、`KEYBEN_PASSWORD`、`KEYBEN_NEW_PASSWORD`、`KEYBEN_CONFIG_PASSWORD` 会被移除，避免一个打印环境变量的子进程把它们暴露出去。如果项目里确实存了同名的密钥，显式值优先，仍然会生效。

### 更换项目密码

```bash
keyben password reset --projectName myapp \
  --password 'current-password' --new-password 'new-password'
```

任一密码省略时会安全提示输入。因为值是用每项目的 DEK 加密而非直接用密码，重置只是重新派生密钥并用新密码重新包裹**同一个 DEK** —— 存储的密文完全不动，所以又快又不会产生半损坏状态。当前密码不正确会被服务端拒绝。自动化可以用 `KEYBEN_NEW_PASSWORD` 传入新密码。

> 工作目录下的 `.keyben.toml` 仍然停留在旧密码上，重置后用 `keyben config init` 重新生成。

### 自签名证书

```bash
keyben --insecure secrets get --projectName myapp --env dev --name DB_URL
```

`--insecure` 跳过 TLS 证书校验，只在证书自签且链路本身可控时使用。生产环境请安装受信任的 CA 证书。

## License

keyben 基于 [MIT License](LICENSE) 发布。