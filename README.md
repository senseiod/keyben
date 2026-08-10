# Keyben

English | [简体中文](README_CN.md)

**Keyben is an end-to-end encrypted secrets management tool written in Rust.** It ships as a single binary that works as both server and client. All encryption and decryption happen on your machine; the server only ever stores ciphertext.

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

> Fetch ciphertext → decrypt locally → inject straight into the child process environment. No `.env` file is ever written.

---

## At a glance

|  |                                                                    |
| --- |--------------------------------------------------------------------|
| **Form** | A single executable, server and client in one |
| **Implementation** | Rust |
| **Storage** | A single SQLite file |
| **Encryption** | Client-side XChaCha20-Poly1305 + Argon2id + envelope encryption |
| **Transport** | HTTP(S) + Bearer token, TLS optional |
| **Platforms** | Linux (glibc / musl), macOS Apple Silicon, Windows x86_64 / ARM64 |
| **License** | MIT |

## Where it fits

keyben is designed primarily for self-hosted personal projects and small teams. It is deliberately small: no complex deployment pipeline, a single binary, SQLite for storage, and strict encryption protecting your secrets — so you can stop worrying about leaking `.env` files and keys.

### How it works

```text
password ──Argon2id(salt)──▶ enc_key ──unwrap──▶ project data key (DEK)
     │                                          │
     ▼                                          ▼
 plaintext ────── client: XChaCha20-Poly1305 ───┘
     │  Base64 ciphertext over HTTP(S) + Bearer token
     ▼
 server: SQLite (salt, wrapped DEK, auth hash, ciphertext)
     │
     ▼
 client: download ciphertext, decrypt locally with the DEK
```

Key derivation:

```text
master_key  = Argon2id(password, project_salt, m=64MiB, t=3, p=4)
enc_key     = HKDF-SHA256(master_key, "keyben v1 kek")    # wraps the DEK, client-side only
auth_secret = HKDF-SHA256(master_key, "keyben v1 auth")   # sent to the server for project auth
```

The two subkeys are domain-separated, so the `auth_secret` the server sees leaks nothing about the encryption key.


### Why keyben?
- Zero server trust by default. The client does all encryption and decryption with XChaCha20-Poly1305 + Argon2id + envelope encryption. The server stores encrypted secrets only.
- Uses zeroize so keys can't be recovered from a core dump.
- An auth_token guards the API against unauthorized calls, and the project password handles both encryption and project authentication.
- `keyben run` hands decrypted values directly to the child process — no `.env` file, no extra files.
- Even if the auth_token leaks, the secrets stay out of reach: the only path left is brute-forcing Argon2id offline, where every guess costs 64 MiB of memory. Brute force isn't a practical worry — just don't pick a weak password.

### Be careful
- **Don't use a weak password.** Argon2id and a per-project salt make each guess expensive and rule out rainbow tables and cross-project key reuse, but short or common passwords still fall to brute force. Use a long random password.
- **Keep the service secure.** The data in the database is encrypted, but once an attacker owns your server they can delete or replace your data, or refuse to return ciphertext. Back up and monitor it yourself.
- **Token leaks.** For simplicity keyben has no users, roles, permission tiers, token rotation, or audit log. If the token leaks, an attacker can use it to fetch encrypted secrets — they still can't break them, but they can write garbage into your server.
- **Use TLS, a reverse proxy, or plain HTTP only in a trusted environment.** Plain HTTP is exposed to replay attacks and eavesdropping; keep it to trusted private networks (Tailscale, for example), or configure TLS.
- **Prefer interactive input.** `--value` / `--password` land in shell history and the process list — use interactive prompts instead.
- **Back up the database and keep the password safe.** Lose either one and nothing can bring your secrets back.

---

## Installation

### Download a prebuilt binary

Grab the archive for your platform from [GitHub Releases](https://github.com/senseiod/keyben/releases).

**Linux / macOS**

```bash
tar -xzf keyben-linux-x86_64.tar.gz
sudo install -m 0755 keyben-linux-x86_64/keyben /usr/local/bin/keyben
keyben --version
```

**Windows** (PowerShell)

```powershell
tar -xzf .\keyben-windows-x86_64.tar.gz
```

Extract it and add the directory to your `PATH`. Every platform is released as a `.tar.gz`; the Windows archives contain `keyben.exe`.

Available packages:

| Package | Target platform |
| --- | --- |
| `keyben-linux-x86_64` | Linux x86_64 (glibc) |
| `keyben-linux-arm64` | Linux ARM64 (glibc) |
| `keyben-linux-musl-x86_64` | Linux x86_64 (musl, e.g. Alpine) |
| `keyben-linux-musl-arm64` | Linux ARM64 (musl) |
| `keyben-macos-arm64` | macOS Apple Silicon |
| `keyben-windows-x86_64` | Windows x86_64 |
| `keyben-windows-arm64` | Windows ARM64 |

Every release also ships `SHA256SUMS` for verification.

### Build from source

Requires a current stable Rust toolchain:

```bash
git clone https://github.com/senseiod/keyben.git
cd keyben
cargo build --locked --release
```

The binary lands at `target/release/keyben`. You can also install it directly:

```bash
cargo install --path . --locked
```

---

## Server

### Configuration

Create `config.toml`:

```toml
[server]

# Listen address and port
listen = "0.0.0.0:8000"

# SQLite file; the parent directory is created automatically
data = "keyben.db"

# HTTP API auth token (required, must not be empty). Generating it with `openssl rand -hex 32` is recommended.
auth_token = "replace-with-a-long-random-token"

# HTTPS is enabled only when both are set; setting just one refuses to start, omitting both uses HTTP
# cert = "/etc/keyben/server.crt"
# key  = "/etc/keyben/server.key"
```

Generate an auth_token:

```bash
openssl rand -hex 32
```

### Starting it

```bash
# Start the server with --config
keyben --config config.toml

# -c works too
keyben -c config.toml

# Run in the foreground with logs
RUST_LOG=keyben=info,tower_http=info keyben -c config.toml
```

On startup it prints the HTTP/HTTPS address and the database path; `Ctrl-C` shuts down gracefully. Don't mix `--config` with client subcommands.
Running the server under systemd is recommended.

> **Note:** `tower_http=debug` writes request paths into the log, which include variable names (but not values). Stick to `info` in production.

### Health checks

`/healthz` sits behind the Bearer token like every other endpoint — an unauthenticated caller can't even probe which projects exist — so your monitoring probe needs the token too:

```bash
curl --fail -H "Authorization: Bearer ${KEYBEN_TOKEN}" http://127.0.0.1:8000/healthz
```

### Backup and restore

The database holds per-project envelope metadata (Argon2 salt, wrapped DEK, auth hash) and the encrypted values. **Back up this SQLite file regularly.**

Restoring requires no re-encryption: put the SQLite file back, start the server with a compatible config, and clients keep using the same project password.

> The password is not stored by keyben and cannot be recovered by the server. Lost password = the wrapped DEK can never be unwrapped = every secret in that project is permanently unreadable.

---

## Client

### Five-minute start

```bash
# (Optional) configure via environment variables — great for CI and other automation
export KEYBEN_SERVER="https://secrets.example.com"
export KEYBEN_TOKEN="the auth_token from the server's config.toml"
export KEYBEN_PASSWORD="the project's password"

# 1. Create a project (omit any flag and keyben asks for it)
keyben init --projectName myapp

# 2. Store a secret
keyben secrets set --projectName myapp --env dev --name DB_URL --value 'postgres://user:pw@db.example.com/app' --password 123456
# or
keyben secrets set --projectName myapp --env dev

# 3. Read a secret
keyben secrets get --projectName myapp --env dev --name DB_URL
# or read them all
keyben secrets get --projectName myapp --env dev

# 4. Pass the secrets to your service
keyben run --projectName myapp --env dev -- npm run dev

# Extras

# Add the project to ~/.keyben.toml so next time you only need its name and password.
# The values are verified against the server before the file is written.
keyben config init --projectName myapp
```

### Command overview

| Command | What it does |
| --- | --- |
| `keyben init` | Create a project on the server and set its password |
| `keyben config init` | Verify the values, then add the project to the per-user `~/.keyben.toml` file |
| `keyben secrets set` | Encrypt and store a variable |
| `keyben secrets get` | Fetch and decrypt one variable, or a whole environment |
| `keyben secrets delete` | Delete a variable |
| `keyben password reset` | Change the project password (ciphertext untouched) |
| `keyben run -- <cmd>` | Inject decrypted environment variables and launch a child process |

Global options: `--server` / `--token` / `--password` / `--insecure`, matching the environment variables `KEYBEN_SERVER`, `KEYBEN_TOKEN`, `KEYBEN_PASSWORD`, and `KEYBEN_INSECURE`.

### Nothing is required on the command line

Every command can be started bare. A value you don't pass is asked for instead of rejected, so you never have to look up a flag name to make progress:

```bash
# Prompts for the server, token, project name, and password in turn
keyben init

# Prompts for the project name, environment, variable name, and value
keyben secrets set
```

Environments are chosen from a list rather than typed, and passwords and tokens are read without echoing. Values already supplied — as flags, as `KEYBEN_*` environment variables, or from the selected project in `~/.keyben.toml` — are never asked about again, so automation stays non-interactive. When there's no terminal to prompt on, the error names the flag and the environment variable that would have supplied the value.

The one exception is `keyben run`: the program after `--` is still required, since there's no sensible way to prompt for a command line along with its argument boundaries.

```bash
keyben run -- npm run dev   # prompts for project name and environment
```

### Per-user multi-project configuration

If you'd rather not pass `--server` and `--token` every time, add the project to the per-user config file. Linux and macOS use `~/.keyben.toml`; Windows uses `%USERPROFILE%\.keyben.toml`:

```bash
keyben config init --projectName myapp
```

Anything you omit is asked for interactively. The server address and token are encrypted using the **project password concatenated with the current machine UID** as the Argon2id input, and every project has an independent salt. The UID comes from `machine-uid` and is not stored in the file. One file can hold multiple projects:

```toml
[myapp]
salt = "Base64 salt"
encrypted_server = "encrypted server URL"
encrypted_token = "encrypted auth_token"

[another-project]
salt = "Base64 salt"
encrypted_server = "encrypted server URL"
encrypted_token = "encrypted auth_token"
```

Initializing the same project again asks before replacing only that section; other projects are preserved. The file does not select a default project, so pass `--projectName` or enter the project name interactively when running a command.

Every value is checked against the server before anything is written. A single unlock attempt exercises all four at once, so each failure is reported where the mistake was made rather than on some later command:

| What's wrong | What you see |
| --- | --- |
| Server unreachable or the URL is wrong | `Request to server failed: <url>` |
| Token doesn't match the server's `auth_token` | `Authentication failed (401)` |
| Project doesn't exist on that server | ``Project `myapp` does not exist`` |
| Wrong project password | `Failed to unlock the project; incorrect password` |

If verification fails, the file is not created or modified, and the error says so explicitly. There's no flag to skip the check — a saved entry that looks right but holds a bad token is exactly the failure this prevents.

You can then run commands from any directory. This reads `[myapp]`, asks for the password once, and uses it to decrypt server/token and unlock the project:

```bash
keyben secrets get --projectName myapp --env dev
# Non-interactive use
keyben secrets get --projectName myapp --password "$KEYBEN_PASSWORD" --env dev
```

Resolution order:

```text
explicit command-line flags such as --server / --token > KEYBEN_SERVER / KEYBEN_TOKEN environment variables > project section in the user config file
```

For automation, use `--password` or `KEYBEN_PASSWORD` to skip the prompt.

> **This file contains no project DEK.** Every section uses an independent Argon2id salt and a key unrelated to the project master key; the project DEK always stays wrapped on the server. The config is bound to the device that created it. Copying it to another device, entering the wrong password, or changing the machine UID reports `Project password is incorrect`; run `keyben config init` again. Keyben does not set or modify permissions on this file.

### Managing secrets

**Write / overwrite**

```bash
keyben secrets set --projectName myapp --env dev \
  --name DB_URL --value 'postgres://user:pw@db.example.com/app'
```

The value is encrypted locally before it leaves your machine. `--env` accepts only `dev` or `prod`.

In an interactive terminal every flag can be omitted: keyben asks which environment, prompts for the variable name, and reads the value without echoing it — **the recommended way**, since it keeps plaintext out of your shell history:

```bash
keyben secrets set
```

**Read a single value**

```bash
keyben secrets get --projectName myapp --env dev --name DB_URL
```

The decrypted plaintext is printed to standard output.

**Read a whole environment**

```bash
keyben secrets get --projectName myapp --env dev
```

Output is sorted by variable name in `KEY=VALUE` form. Values containing newlines naturally span multiple lines.

**Delete**

```bash
keyben secrets delete --projectName myapp --env dev --name DB_URL
```

### Running a child process

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

Everything after `--` is the subcommand and its arguments. keyben fetches and decrypts the whole environment, launches the child process, and passes through its exit code.

The child inherits the caller's environment plus the decrypted secrets, **minus keyben's own credentials**: every variable whose name starts with `KEYBEN` is removed, so a child process that dumps its environment can't expose the token or the project password. It's a prefix rule rather than a fixed list, so a credential added in a later version can't quietly start leaking. If your project genuinely stores a secret under such a name, the explicit value wins and is still applied.

### Changing the project password

```bash
keyben password reset --projectName myapp \
  --password 'current-password' --new-password 'new-password'
```

Either password is prompted for securely when omitted. Because values are encrypted with the per-project DEK rather than the password itself, a reset just re-derives the key and re-wraps **the same DEK** under the new password — the stored ciphertext is untouched, which makes it fast and free of half-broken states. An incorrect current password is rejected by the server. For automation, pass the new password via `KEYBEN_NEW_PASSWORD`.

> That project's section in `~/.keyben.toml` is still encrypted under the old password. After a reset, update it with `keyben config init --projectName <name>`; other projects are unaffected.

### Self-signed certificates

```bash
keyben --insecure secrets get --projectName myapp --env dev --name DB_URL
```

`--insecure` skips TLS certificate verification. Use it only when the certificate is self-signed and you control the network path. In production, install a trusted CA certificate.

## License

keyben is released under the [MIT License](LICENSE).
