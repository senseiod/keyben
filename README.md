# keyben

keyben is a self-hosted environment-variable and secret management tool written in Rust. It is distributed as a single binary that can run either as a storage server or as a command-line client.

The client encrypts every secret before sending it to the server. The server stores and returns Base64-encoded ciphertext plus public per-project envelope metadata (an Argon2 salt, a wrapped data key, and an authentication hash), but never receives the encryption password or plaintext value.

## Highlights

- **End-to-end encryption:** XChaCha20-Poly1305 with associated data binding each value to its `(project, env, name)` slot, so ciphertext cannot be relocated.
- **Argon2id key derivation** (64 MiB, memory-hard, per-project salt) instead of a bare hash.
- **Envelope encryption:** one random data key (DEK) encrypts every value; the password only wraps that key, so a password reset re-wraps the DEK and never rewrites secret ciphertext.
- **Two independent credentials:** a Bearer token gates the server; a per-project password gates the data.
- **Single binary** for both server and client, backed by SQLite with no separate database service.
- **Safe process injection:** `keyben run` passes decrypted values straight to a child process instead of writing a `.env` file.
- **Portable:** Linux GNU and musl, macOS Apple Silicon, and Windows ARM64/x86_64 release artifacts.

## How it works

```text
password ──Argon2id(salt)──▶ enc_key ──unwraps──▶ project data key (DEK)
        │                                                  │
        ▼                                                  ▼
plaintext ────────────── client: XChaCha20-Poly1305 ──────┘
        │  Base64 ciphertext over HTTP(S) + Bearer Token
        ▼
server: SQLite storage (salt, wrapped DEK, auth hash, ciphertext)
        │
        ▼
client: download ciphertext and decrypt locally with the DEK
```

## Security model

keyben uses two credentials that protect different things and cannot substitute for each other.

| Credential | Where it lives | What it protects |
| --- | --- | --- |
| `auth_token` | `config.toml` on the server; `--token`/`KEYBEN_TOKEN`/`.keyben.toml` on the client | Reachability of the server. Every endpoint, including `/healthz`, returns 401 without it, so an unauthenticated party cannot even confirm which projects exist. |
| Project password | Never stored anywhere; entered by the user | Confidentiality of the data. It derives the key that unwraps the DEK, and a separate derived value that authenticates project requests. |

The key schedule is:

```text
master_key  = Argon2id(password, project_salt, m=64MiB, t=3, p=4)
enc_key     = HKDF-SHA256(master_key, "keyben v1 kek")    # wraps the DEK, client only
auth_secret = HKDF-SHA256(master_key, "keyben v1 auth")   # sent to the server
```

The server stores `SHA-256(auth_secret)`, so even a full database leak yields no replayable credential. The two subkeys are domain-separated, so the value the server sees reveals nothing about the encryption key.

An attacker holding only the token can download ciphertext but cannot read it: values are encrypted with the DEK, the DEK is wrapped by `enc_key`, and the password never leaves the client. Their only path forward is an offline attack against Argon2id, paying 64 MiB of memory per guess. An attacker holding only the password cannot reach the server at all.

## Advantages

- **Simple deployment:** one executable and one TOML file; no separate database service is required.
- **Small attack surface:** the server exposes only project and secret CRUD endpoints and implements no user accounts or browser UI.
- **Cheap password rotation:** re-keying touches one database row, so it cannot partially corrupt data.
- **Portable:** official release archives cover common Linux, musl, macOS ARM64, and Windows targets.

## Limitations and trade-offs

- **The password is still the weakest link.** Argon2id makes each guess expensive and the per-project salt prevents rainbow tables and cross-project key reuse, but neither makes a short or common password safe. Use a long, randomly generated one.
- **The token is not an identity system.** There are no users, roles, token rotation, or audit logs.
- **The server is not trusted for availability or integrity.** It can delete, replace, or withhold ciphertext even though it cannot decrypt it. Use backups and monitoring.
- **TLS is optional.** Without `cert` and `key`, the server speaks plaintext HTTP. Only use that on a trusted private network such as Tailscale.
- **Command-line values can leak.** Anything passed via `--value`, `--password`, or an environment variable may appear in shell history, process listings, or CI logs. Prefer the interactive prompt and a protected automation secret store.
- **Environments are limited to `dev` and `prod`,** and there is no secret versioning, rotation workflow, high availability, or remote backup.

keyben is a good fit for a small self-hosted deployment or an internal network. It is not a full enterprise KMS, IAM system, or multi-tenant secrets platform.

## Installation

### Install a release binary

Download the archive for your platform from the [GitHub Releases](https://github.com/senseiod/keyben/releases) page, extract it, and place the `keyben` executable on your `PATH`.

On Linux or macOS:

```bash
tar -xzf keyben-linux-x86_64.tar.gz
sudo install -m 0755 keyben-linux-x86_64/keyben /usr/local/bin/keyben
keyben --version
```

Substitute the archive name matching your CPU and libc variant. The `linux-musl-*` archives are intended for musl-based systems such as Alpine Linux.

On Windows, extract the `windows-x86_64` or `windows-arm64` archive and add its directory to `PATH`. For example, in PowerShell:

```powershell
tar -xzf .\keyben-windows-x86_64.tar.gz
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

For a project-local setup, create an encrypted `.keyben.toml` file:

```bash
keyben config init \
  --projectName frontierkings \
  --server http://example.com \
  --token 123456
```

Any omitted value is requested interactively. The command encrypts the server URL and token under the **project password** before writing the file, so there is only one password to remember. The project name stays in plaintext so it can serve as the default project identifier. If `.keyben.toml` already exists, keyben asks before overwriting it.

When a client command runs in the directory containing `.keyben.toml`, keyben asks for the project password once and uses it both to decrypt the file and to unlock the project. Explicit command-line values take precedence, followed by `KEYBEN_SERVER`/`KEYBEN_TOKEN`, and then the project-local file. Use `--password` or `KEYBEN_PASSWORD` for non-interactive use.

The file is encrypted with its own Argon2id salt, so its key is independent of the project master key even though both derive from the same password. It holds no key material: the project data key stays wrapped on the server, so someone who cracks this file gains the token's reach but still cannot decrypt any secret. keyben does not assign it special filesystem permissions; do not commit it unless that is intentional.

`keyben password reset` changes the project password on the server but does not rewrite `.keyben.toml`. Recreate the file with `keyben config init` afterwards, as the command's output reminds you.

Each project has one password. During `init`, keyben asks for the password twice, derives the project keys locally with Argon2id, and sends the server only public envelope metadata (salt, wrapped data key, and an authentication hash). The password itself is never sent to or stored by the server. If `--password` or `KEYBEN_PASSWORD` is not provided for `secrets` or `run`, keyben prompts for it interactively without echoing it:

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

Project creation is exclusive: once a project name is taken, `init` for that name is rejected. Existing secrets are never touched.

Project names are trimmed of surrounding whitespace on every path, so `myapp` and `' myapp '` refer to the same project rather than silently diverging.

### Reset a project password

```bash
keyben password reset \
  --projectName myapp \
  --password 'current-password' \
  --new-password 'new-password'
```

When either password option is omitted, keyben prompts securely. Because secrets are encrypted with a per-project data key rather than the password directly, the reset only re-derives keys and re-wraps that same data key under the new password — the stored secret ciphertext is left untouched, so the operation is fast and cannot partially corrupt data. An incorrect current password is rejected by the server. For automation, the new password can also be provided through `KEYBEN_NEW_PASSWORD`. Any `.keyben.toml` in the working directory keeps its old password until you recreate it with `keyben config init`.

### Set or overwrite a secret

```bash
keyben secrets set \
  --projectName myapp \
  --env dev \
  --name DB_URL \
  --value 'postgres://user:password@db.example.com/app'
```

The value is encrypted locally before the HTTP request is sent. The project password is checked by the server before the ciphertext is stored. `--env` accepts `dev` or `prod`.

Both `--name` and `--value` are optional in an interactive terminal. When omitted, keyben prompts for the variable name and reads the value without echoing it:

```bash
keyben secrets set --projectName myapp --env dev
```

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

The child inherits the caller's environment plus the decrypted secrets, minus keyben's own credentials: `KEYBEN_TOKEN`, `KEYBEN_PASSWORD`, `KEYBEN_NEW_PASSWORD`, and `KEYBEN_CONFIG_PASSWORD` are removed so a child that dumps its environment cannot expose them. A secret stored under one of those names still takes effect — an explicit value wins over the ambient one.

### Use a self-signed internal HTTPS certificate

```bash
keyben --insecure secrets get \
  --projectName myapp \
  --env dev \
  --name DB_URL
```

Use `--insecure` only when the certificate is self-signed and the connection is otherwise controlled. Prefer installing a trusted CA certificate for production use.

## Data and recovery

The server database contains per-project envelope metadata (Argon2 salt, wrapped data key, authentication hash) and encrypted secret values. Back up the SQLite file regularly, along with the server configuration needed to operate it. The encryption password is not stored by keyben and cannot be recovered by the server; losing it makes the wrapped data key — and therefore all ciphertext for that project — unreadable.

Restoring a database does not require re-encrypting secrets. Restore the SQLite file, start the server with a compatible configuration, and use the original encryption password from the client.

### Storage format

The current format is v2 (Argon2id key derivation and envelope encryption). It is not backward compatible with databases or `.keyben.toml` files written by v0.1.x, and no migration path is provided: start the server on a fresh database path, re-run `keyben init` per project, re-enter the secrets, and recreate any project-local file with `keyben config init`.

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
