# keyben

keyben is a self-hosted environment-variable and secret management tool written in Rust. It is distributed as a single binary that can run either as a storage server or as a command-line client.

The client encrypts every secret before sending it to the server. The server stores and returns Base64-encoded ciphertext plus a project-bound password verification hash, but never receives the encryption password or plaintext value.

## Highlights

- End-to-end encryption on the client using ChaCha20-Poly1305.
- A SHA-256-derived 32-byte key and a fresh random nonce for every value.
- SQLite-backed server with a small HTTP API and project password verification.
- Bearer Token authentication on every endpoint, including `/healthz`.
- Optional TLS with a PEM certificate and private key.
- `keyben run` injects decrypted values into a child process without writing a `.env` file.
- One binary for both server and client modes.
- Linux GNU and musl, macOS Apple Silicon, and Windows ARM64/x86_64 release artifacts.

## How it works

```text
password + plaintext
        │
        ▼
client: ChaCha20-Poly1305 encryption
        │  Base64 ciphertext over HTTP(S) + Bearer Token
        ▼
server: SQLite storage
        │
        ▼
client: download ciphertext and decrypt locally
```

The server is intentionally unable to decrypt values. Anyone who needs to read a secret needs both the server authentication token and the encryption password.

## Advantages

- **Simple deployment:** one executable and one TOML file; no separate database service is required.
- **Encrypted server storage:** the SQLite database contains ciphertext and password verification hashes rather than plaintext credentials.
- **Small attack surface:** the server exposes only project and secret CRUD endpoints and does not implement user accounts or a browser UI.
- **Safe process injection:** `run` passes values directly to the child process instead of creating a plaintext configuration file.
- **Portable:** official release archives cover common Linux, musl, macOS ARM64, and Windows targets.

## Limitations and trade-offs

- **The password KDF is intentionally small and simple:** the current implementation hashes the password once with SHA-256. It does not use a slow password-hashing function such as Argon2 or scrypt, so weak passwords are vulnerable to offline brute-force attacks if the database, ciphertext, or project verification hash is obtained. Use a long, randomly generated password.
- **Bearer Token authentication is not an identity system:** there are no users, roles, token rotation, or audit logs. Access to project secrets additionally requires that project's password verification value.
- **The server is not trusted for availability or integrity:** it can delete, replace, or withhold ciphertext even though it cannot decrypt it. Use backups and monitoring for important deployments.
- **TLS is optional:** without `cert` and `key`, the server uses plaintext HTTP. Only expose that mode on a trusted private network such as Tailscale, or configure TLS.
- **Command-line values can leak:** values passed through `--value`, `--password`, or environment variables may be visible in shell history, process listings, CI logs, or crash reports. Prefer the interactive password prompt and a protected automation secret store.
- **Environments are currently limited to `dev` and `prod`.**
- **No built-in high availability, secret versioning, rotation workflow, or remote backup is provided.**

keyben is a good fit for a small self-hosted deployment or an internal network. It is not a full enterprise KMS, IAM system, or multi-tenant secrets platform.

## Installation

### Install a release binary

Download the archive for your platform from the [GitHub Releases](https://github.com/senseiod/keyben/releases) page, extract it, and place the `keyben` executable on your `PATH`.

On Linux or macOS:

```bash
tar -xzf keyben-v0.1.0-linux-x86_64.tar.gz
sudo install -m 0755 keyben-v0.1.0-linux-x86_64/keyben /usr/local/bin/keyben
keyben --version
```

Choose the matching archive name for your CPU and libc variant. The `linux-musl-*` archives are intended for musl-based systems such as Alpine Linux.

On Windows, extract the `windows-x86_64` or `windows-arm64` archive and add its directory to `PATH`. For example, in PowerShell:

```powershell
tar -xzf .\keyben-v0.1.0-windows-x86_64.tar.gz
```

The official release archives use `.tar.gz` for all platforms; Windows also includes the `keyben.exe` executable inside the archive.

### Build from source

Install the current stable Rust toolchain, then run:

```bash
git clone https://github.com/senseiod/keyben.git
cd keyben
cargo build --locked --release
```

The compiled binary is located at `target/release/keyben`. You can also install it with:

```bash
cargo install --path . --locked
```

## Server setup

### Configuration file

Create `/etc/keyben/config.toml`:

```toml
[server]

# Address and port to bind.
listen = "0.0.0.0:8000"

# SQLite file. Parent directories are created automatically.
data = "/var/lib/keyben/keyben.db"

# Required HTTP API authentication token.
auth_token = "replace-with-a-long-random-token"

# Configure both fields to enable HTTPS. Leave both out to use HTTP.
# cert = "/etc/keyben/server.crt"
# key = "/etc/keyben/server.key"
```

Generate a token with a local tool instead of using a short human-readable value:

```bash
openssl rand -hex 32
```

`auth_token` must not be empty. `cert` and `key` must either both be configured or both omitted. The server refuses to start if only one TLS file is present.

### Start the server

The same executable starts the server when `--config` or `-c` is supplied:

```bash
keyben --config /etc/keyben/config.toml
```

For a foreground service with logs:

```bash
RUST_LOG=keyben=info,tower_http=info \
  keyben -c /etc/keyben/config.toml
```

The server logs its HTTP or HTTPS address and the database path. Press `Ctrl-C` for a graceful shutdown. Do not combine `--config` with a client subcommand.

The health endpoint is protected by the same Bearer Token as every other endpoint:

```bash
curl --fail \
  -H "Authorization: Bearer ${KEYBEN_TOKEN}" \
  http://127.0.0.1:8000/healthz
```

When using a self-signed certificate during internal testing, the client can skip certificate verification with `--insecure`. Do not use that option on an untrusted network.

## Client configuration

The client needs the server URL and API token. They can be supplied globally on each command or through environment variables:

```bash
export KEYBEN_SERVER="https://secrets.example.com"
export KEYBEN_TOKEN="replace-with-the-server-auth-token"
```

Each project has one password. During `init`, keyben asks for the password twice and stores only a project-bound SHA-256 verification hash on the server. The password itself is never sent to or stored by the server. If `--password` or `KEYBEN_PASSWORD` is not provided for `secrets` or `run`, keyben prompts for it interactively without echoing it:

```bash
keyben secrets get --projectName myapp --env prod --name DB_URL
```

For automation, set `KEYBEN_PASSWORD` through the CI system's protected secret mechanism. Avoid committing passwords, tokens, or plaintext values to shell scripts or repository files.

## Common client commands

All commands below assume `KEYBEN_SERVER` and `KEYBEN_TOKEN` are set. A project must exist before secrets can be written.

### Create a project

```bash
keyben init --projectName myapp
```

Project creation is idempotent when the same password is supplied again; a different password is rejected. Running it again does not remove existing secrets.

### Reset a project password

```bash
keyben password reset \
  --projectName myapp \
  --password 'current-password' \
  --new-password 'new-password'
```

When either password option is omitted, keyben prompts securely. The client downloads and decrypts every secret in both `dev` and `prod`, re-encrypts each value with the new password, then asks the server to atomically replace all ciphertext and the project password verification hash. If any secret cannot be decrypted or the project changes during the reset, nothing is updated. For automation, the new password can also be provided through `KEYBEN_NEW_PASSWORD`.

### Set or overwrite a secret

```bash
keyben secrets set \
  --projectName myapp \
  --env dev \
  --name DB_URL \
  --value 'postgres://user:password@db.example.com/app'
```

The value is encrypted locally before the HTTP request is sent. The project password is checked by the server before the ciphertext is stored. `--env` accepts `dev` or `prod`.

### Read one secret

```bash
keyben secrets get \
  --projectName myapp \
  --env dev \
  --name DB_URL
```

The decrypted plaintext is printed to standard output.

### Read every secret in an environment

```bash
keyben secrets get \
  --projectName myapp \
  --env dev
```

Output uses `KEY=VALUE` form and is sorted by variable name. Values containing newline characters naturally span multiple output lines.

### Delete a secret

```bash
keyben secrets delete \
  --projectName myapp \
  --env dev \
  --name DB_URL
```

### Run a command with decrypted environment variables

```bash
keyben run \
  --projectName myapp \
  --env prod \
  -- ./server --port 8080
```

Everything after `--` is treated as the child command and its arguments. keyben fetches and decrypts the environment, starts the child process, and propagates its exit code.

### Use a self-signed internal HTTPS certificate

```bash
keyben --insecure secrets get \
  --projectName myapp \
  --env dev \
  --name DB_URL
```

Use `--insecure` only when the certificate is self-signed and the connection is otherwise controlled. Prefer installing a trusted CA certificate for production use.

## Data and recovery

The server database contains project password verification hashes and encrypted secret values. Back up the SQLite file regularly, along with the server configuration needed to operate it. The encryption password is not stored by keyben and cannot be recovered by the server; losing it makes the corresponding ciphertext unreadable.

Restoring a database does not require re-encrypting secrets. Restore the SQLite file, start the server with a compatible configuration, and use the original encryption password from the client.

## Releases

Pushing a tag matching `v*` runs the GitHub Actions release pipeline. Each release contains packaged, release-mode binaries for the following targets:

| Artifact | Rust target | Runtime |
| --- | --- | --- |
| `linux-x86_64` | `x86_64-unknown-linux-gnu` | Linux x86_64, glibc-based Unix-compatible systems |
| `linux-arm64` | `aarch64-unknown-linux-gnu` | Linux ARM64, glibc-based Unix-compatible systems |
| `macos-arm64` | `aarch64-apple-darwin` | macOS Apple Silicon |
| `windows-arm64` | `aarch64-pc-windows-msvc` | Windows ARM64 |
| `windows-x86_64` | `x86_64-pc-windows-msvc` | Windows x86_64 |
| `linux-musl-x86_64` | `x86_64-unknown-linux-musl` | Linux x86_64 with musl |
| `linux-musl-arm64` | `aarch64-unknown-linux-musl` | Linux ARM64 with musl |

Every archive includes the `keyben` binary, this README, and the MIT license. The release also publishes a `SHA256SUMS` file for artifact verification.

## License

keyben is released under the [MIT License](LICENSE).
