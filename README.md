# keyben

keyben is a self-hosted environment-variable and secret management tool written in Rust. It is distributed as a single binary that can run either as a storage server or as a command-line client.

The client derives a project key with Argon2id and encrypts every secret before sending it to the server. The server stores KDF metadata, an encrypted project-password verifier, and Base64-encoded ciphertext, but never receives the project password or plaintext values.

## Highlights

- End-to-end encryption on the client using ChaCha20-Poly1305.
- An Argon2id-derived 32-byte project master key with a random salt.
- A distinct encryption key derived for each secret from its project, environment, and name.
- A fresh random nonce and authenticated context for every value.
- SQLite-backed server with a small HTTP API.
- Bearer Token authentication on every endpoint, including `/healthz`.
- Optional TLS with a PEM certificate and private key.
- Interactive prompts for omitted secret names, secret values, and project passwords.
- `keyben run` injects decrypted values into a child process without writing a `.env` file.
- One binary for both server and client modes.
- Linux GNU and musl, macOS Apple Silicon, and Windows ARM64/x86_64 release artifacts.

## How it works

```text
project password + project salt
        │
        ▼
client: Argon2id derives the project key
        │
        ├── verifier subkey encrypts the project verifier
        └── per-secret subkeys encrypt with ChaCha20-Poly1305
                │  Base64 ciphertext over HTTP(S) + Bearer Token
        ▼
server: SQLite storage
        │
        ▼
client: verify the project password, then decrypt locally
```

The server is intentionally unable to decrypt values. Anyone who needs to read a secret needs both the server authentication token and the project password.

## Advantages

- **Simple deployment:** one executable and one TOML file; no separate database service is required.
- **Encrypted server storage:** the SQLite database contains ciphertext rather than plaintext credentials.
- **Small attack surface:** the server exposes only project and secret CRUD endpoints and does not implement user accounts or a browser UI.
- **Safe process injection:** `run` passes values directly to the child process instead of creating a plaintext configuration file.
- **Portable:** official release archives cover common Linux, musl, macOS ARM64, and Windows targets.

## Limitations and trade-offs

- **Password strength still matters:** Argon2id makes offline password guessing more expensive, but it cannot make a weak password strong. Use a long, randomly generated project password.
- **Bearer Token authentication is not an identity system:** there are no users, roles, per-project permissions, token rotation, or audit logs. Anyone with the token can access every project on the server.
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
cargo build --release
```

The compiled binary is located at `target/release/keyben`. You can also install it with:

```bash
cargo install --path .
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

The project password is deliberately not stored in the config file. If `--password` or `KEYBEN_PASSWORD` is not provided, keyben prompts for it interactively without echoing it:

```bash
keyben secrets get --projectName myapp --env prod --name DB_URL
```

For automation, set `KEYBEN_PASSWORD` through the CI system's protected secret mechanism. Avoid committing passwords, tokens, or plaintext values to shell scripts or repository files.

## Common client commands

All commands below assume `KEYBEN_SERVER` and `KEYBEN_TOKEN` are set. A project must exist before secrets can be written.

### Create a project and set its password

```bash
keyben init --projectName myapp
```

keyben prompts for the project password twice and stores only the Argon2id salt, KDF parameters, and an encrypted password verifier. The password itself never leaves the client. A project cannot be initialized twice; use a new database project name if the project already exists.

For non-interactive setup, provide the password through a protected environment variable or `--password`:

```bash
KEYBEN_PASSWORD='use-a-long-random-password' \
  keyben init --projectName myapp
```

### Set or overwrite a secret

For scripts and other non-interactive environments, provide both the name and value explicitly:

```bash
keyben secrets set \
  --projectName myapp \
  --env dev \
  --name DB_URL \
  --value 'postgres://user:password@db.example.com/app'
```

The project password is verified before the value is encrypted. The value is then encrypted locally with the project key before the HTTP request is sent. `--env` accepts `dev` or `prod`.

For interactive use, omit `--name` and/or `--value`. keyben prompts for each missing field and hides the secret value while it is entered:

```bash
keyben --server http://b-server.tailcab45.ts.net:4000 \
  secrets set \
  --env dev \
  --projectName frontierkings \
  --token 1234567
```

Example prompts (the project password is verified first):

```text
Enter the project password: [hidden]
Enter the secret name: API_TOKEN
Enter the secret value: [hidden]
```

Supplying only one option is also supported. For example, this command asks only for the value:

```bash
keyben secrets set \
  --projectName myapp \
  --env dev \
  --name API_TOKEN
```

In CI or another non-interactive environment, always supply `--name` and `--value`; otherwise the command fails when it cannot open an interactive terminal.

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

Deleting a secret also requires the correct project password. The client verifies it before sending the delete request.

If the password is wrong, the command stops before reading, writing, or deleting any secret:

```text
Error: Invalid project password or corrupted project metadata
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

The server database contains project KDF metadata, encrypted password verifiers, and encrypted secret values. Back up the SQLite file regularly, along with the server configuration needed to operate it. The project password is not stored by keyben and cannot be recovered by the server; losing it makes the corresponding ciphertext unreadable.

Restoring a database does not require re-encrypting secrets. Restore the SQLite file, start the server with a compatible configuration, and use the original project password from the client. This database schema is intentionally not backward-compatible with databases created by older keyben builds; move or replace the old database file before upgrading if you need to retain it.

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
