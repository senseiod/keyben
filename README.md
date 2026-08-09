# keyben

Self-hosted storage for environment variables, encrypted end to end. One Rust binary is both the server and the client. Values are encrypted before they leave your machine, so the server holds ciphertext it cannot read.

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

That fetches the encrypted values for `myapp/prod`, decrypts them locally, and passes them to `./server` as environment variables. No `.env` file is written.

---

## Type

|  |  |
| --- | --- |
| Form | Single executable, server and client in one |
| Language | Rust, edition 2024, no runtime dependencies |
| Storage | One SQLite file, no separate database service |
| Crypto | XChaCha20-Poly1305, Argon2id, envelope encryption, client-side |
| Transport | HTTP or HTTPS with a Bearer token |
| Platforms | Linux (glibc, musl), macOS Apple Silicon, Windows x86_64 and ARM64 |
| License | MIT |

## What it is for

keyben is built for self-hosted personal projects and small teams: a few servers, a few projects, a dev and a prod environment. If you want your `.env` files out of Git and out of chat logs but running Vault for three services is overkill, this is about the right size.

There are no user accounts, no web UI, and no plugins. One binary, one TOML file, one SQLite file.

### Why keyben

The server does not have to be trusted. Key derivation and encryption happen in the client. What the server receives is Base64 ciphertext plus public envelope metadata: an Argon2 salt, a wrapped data key, and an authentication hash. The password is never sent and never stored.

Two credentials do different jobs. The `auth_token` controls who can reach the server. The project password controls who can read the data. Someone with only the token can download ciphertext but not decrypt it. Someone with only the password cannot reach the server.

Each project has one random data key (DEK) that encrypts every value, and the password only wraps that key. A password change re-wraps the same DEK, so it touches one database row and rewrites no ciphertext.

Every value is encrypted with its `(project, env, name)` bound in as associated data. Copying the stored bytes from `prod/DB_URL` into `dev/OTHER` fails to decrypt rather than leaking.

### Advantages

- The server never sees a plaintext value or a password.
- A stolen `auth_token` gets an attacker ciphertext, not contents. Reading it means guessing the project password against Argon2id at 64 MiB per attempt.
- A stolen database yields no replayable project credential. The server stores `SHA-256(auth_secret)`, not `auth_secret` itself.
- Ciphertext cannot be moved between projects, environments, or names.
- Password changes are one row update, so they cannot leave data half-converted.
- `keyben run` hands decrypted values straight to a child process, with no temporary file in between.
- Deployment is one executable and one TOML file. The server exposes project and secret CRUD and nothing else.

### Limitations

- A weak password is still weak. Argon2id and a per-project salt make each guess expensive and rule out rainbow tables and cross-project key reuse, but short or common passwords fall anyway. Use a long random one.
- Zeroization is best effort. Derived keys, the DEK, passwords, and decrypted values are wiped when they go out of scope, but the operating system may already have copied a page to swap, and a value handed to a child process lives on in that child.
- The server is not trusted for availability or integrity. It cannot read your data, but it can delete it, withhold it, or return something else. Keep backups.
- The token is not an identity system. No users, roles, scopes, token rotation, or audit logs.
- TLS is optional. Without `cert` and `key` the server speaks plaintext HTTP, and the project authentication header can then be replayed by anyone on the same network.
- `.keyben.toml` is written with the system default permissions, usually `0644`.
- Values passed as `--value` or `--password` reach shell history and process listings. The interactive prompts avoid that.
- No secret versioning, automatic rotation, high availability, or remote backup. Environments are fixed to `dev` and `prod`.

### How it works

```text
password ──Argon2id(salt)──▶ enc_key ──unwraps──▶ project data key (DEK)
        │                                                  │
        ▼                                                  ▼
plaintext ────────────── client: XChaCha20-Poly1305 ───────┘
        │  Base64 ciphertext over HTTP(S) + Bearer token
        ▼
server: SQLite (salt, wrapped DEK, auth hash, ciphertext)
        │
        ▼
client: download ciphertext and decrypt locally with the DEK
```

The key schedule:

```text
master_key  = Argon2id(password, project_salt, m=64MiB, t=3, p=4)
enc_key     = HKDF-SHA256(master_key, "keyben v1 kek")    # wraps the DEK, client only
auth_secret = HKDF-SHA256(master_key, "keyben v1 auth")   # sent to the server
```

The two subkeys are domain-separated, so the `auth_secret` the server sees reveals nothing about the key protecting your data.

---

## Installation

### Release binaries

Download the archive for your platform from [Releases](https://github.com/senseiod/keyben/releases).

On Linux or macOS:

```bash
tar -xzf keyben-linux-x86_64.tar.gz
sudo install -m 0755 keyben-linux-x86_64/keyben /usr/local/bin/keyben
keyben --version
```

On Windows, extract the archive and add its directory to `PATH`:

```powershell
tar -xzf .\keyben-windows-x86_64.tar.gz
```

Every platform ships a `.tar.gz`; the Windows archives contain `keyben.exe`.

| Archive | Platform |
| --- | --- |
| `keyben-linux-x86_64` | Linux x86_64, glibc |
| `keyben-linux-arm64` | Linux ARM64, glibc |
| `keyben-linux-musl-x86_64` | Linux x86_64, musl (Alpine and similar) |
| `keyben-linux-musl-arm64` | Linux ARM64, musl |
| `keyben-macos-arm64` | macOS Apple Silicon |
| `keyben-windows-x86_64` | Windows x86_64 |
| `keyben-windows-arm64` | Windows ARM64 |

Each release also publishes `SHA256SUMS`.

### From source

With a current stable Rust toolchain:

```bash
git clone https://github.com/senseiod/keyben.git
cd keyben
cargo build --locked --release
```

The binary lands in `target/release/keyben`. Or install it directly:

```bash
cargo install --path . --locked
```

---

## Server

### Configuration

Write `/etc/keyben/config.toml`:

```toml
[server]

# Address and port to bind.
listen = "0.0.0.0:8000"

# SQLite file. Parent directories are created automatically.
data = "/var/lib/keyben/keyben.db"

# Required HTTP API token.
auth_token = "replace-with-a-long-random-token"

# Set both to enable HTTPS. Omit both to use HTTP.
# cert = "/etc/keyben/server.crt"
# key  = "/etc/keyben/server.key"
```

| Field | Required | Notes |
| --- | :---: | --- |
| `listen` | yes | Bind address, for example `0.0.0.0:8000` |
| `data` | yes | SQLite path; parent directories are created for you |
| `auth_token` | yes | Bearer token. An empty value refuses to start |
| `cert`, `key` | no | TLS certificate and private key in PEM. Both or neither; one alone refuses to start |

Generate the token instead of inventing one:

```bash
openssl rand -hex 32
```

### Running it

The same executable becomes the server when you pass `-c` or `--config`:

```bash
keyben --config /etc/keyben/config.toml
```

In the foreground with logs:

```bash
RUST_LOG=keyben=info,tower_http=info keyben -c /etc/keyben/config.toml
```

It prints the HTTP or HTTPS address and the database path on startup, and shuts down cleanly on `Ctrl-C`. Do not combine `--config` with a client subcommand.

Keep `tower_http` at `info` in production. At `debug` it logs request paths, which contain variable names, though never values.

### Health checks

`/healthz` sits behind the same Bearer token as every other endpoint, so an unauthenticated caller cannot probe which projects exist. Monitoring probes need the header too:

```bash
curl --fail -H "Authorization: Bearer ${KEYBEN_TOKEN}" http://127.0.0.1:8000/healthz
```

### Backups

The database holds per-project envelope metadata and encrypted values. Back up the SQLite file along with the configuration needed to run it.

Restoring does not require re-encrypting anything: put the file back, start the server, and use the original project password from the client.

The password is not stored by keyben and cannot be recovered by the server. Lose it and the wrapped DEK can never be opened again, which means every value in that project is gone.

---

## Client

### Five minutes in

```bash
# 1. Point the client at your server.
export KEYBEN_SERVER="https://secrets.example.com"
export KEYBEN_TOKEN="the auth_token from the server's config.toml"

# 2. Create a project. This sets the project password, asked twice.
keyben init --projectName myapp

# 3. Store something.
keyben secrets set --projectName myapp --env dev \
  --name DB_URL --value 'postgres://user:pw@db.example.com/app'

# 4. Read it back.
keyben secrets get --projectName myapp --env dev --name DB_URL

# 5. Run your service with the whole environment injected.
keyben run --projectName myapp --env dev -- ./server --port 8080
```

`init` derives the project keys locally with Argon2id and sends the server only public envelope metadata. The password never leaves your machine.

### Commands

| Command | What it does |
| --- | --- |
| `keyben init` | Create a project on the server and set its password |
| `keyben config init` | Write the project-local encrypted `.keyben.toml` |
| `keyben secrets set` | Encrypt and store one variable |
| `keyben secrets get` | Decrypt one variable, or a whole environment |
| `keyben secrets delete` | Remove one variable |
| `keyben password reset` | Change the project password, leaving ciphertext alone |
| `keyben run -- <cmd>` | Inject the decrypted environment and launch a process |

`--server`, `--token`, `--password`, and `--insecure` are global, and also read from `KEYBEN_SERVER`, `KEYBEN_TOKEN`, `KEYBEN_PASSWORD`, and `KEYBEN_INSECURE`.

### Project-local configuration

To avoid exporting variables in every shell, keep an encrypted `.keyben.toml` in the project directory:

```bash
keyben config init --projectName myapp --server https://secrets.example.com --token <TOKEN>
```

Anything omitted is asked for interactively. The server URL and token are encrypted under the project password, so there is still only one password to remember. The project name stays in plaintext so it can act as the default project. If the file already exists, keyben asks before overwriting.

After that, any command run in that directory asks for the project password once and uses it both to decrypt the file and to unlock the project. Explicit flags win, then `KEYBEN_SERVER` and `KEYBEN_TOKEN`, then the file. For automation, supply `--password` or `KEYBEN_PASSWORD`.

The file holds no key material. It has its own Argon2id salt, so its key is unrelated to the project master key, and the project DEK stays wrapped on the server. Cracking this file gets someone the reach of the token and nothing else. keyben does not tighten its permissions, so do not commit it unless you mean to.

### Managing values

Write or overwrite:

```bash
keyben secrets set --projectName myapp --env dev \
  --name DB_URL --value 'postgres://user:pw@db.example.com/app'
```

The value is encrypted before the request goes out. `--env` takes `dev` or `prod`.

In an interactive terminal both `--name` and `--value` can be omitted. keyben prompts for the name and reads the value without echoing it, which keeps the plaintext out of your shell history:

```bash
keyben secrets set --projectName myapp --env dev
```

Read one value, printed to stdout:

```bash
keyben secrets get --projectName myapp --env dev --name DB_URL
```

Read a whole environment, sorted by name as `KEY=VALUE`. Values containing newlines span several lines:

```bash
keyben secrets get --projectName myapp --env dev
```

Delete one:

```bash
keyben secrets delete --projectName myapp --env dev --name DB_URL
```

### Running a process

```bash
keyben run --projectName myapp --env prod -- ./server --port 8080
```

Everything after `--` is the child command and its arguments. keyben fetches and decrypts the environment, starts the child, and exits with the child's status.

The child inherits your environment plus the decrypted values, minus keyben's own credentials: `KEYBEN_TOKEN`, `KEYBEN_PASSWORD`, `KEYBEN_NEW_PASSWORD`, and `KEYBEN_CONFIG_PASSWORD` are removed so a process that dumps its environment cannot expose them. If the project stores a value under one of those names, the explicit value wins and still reaches the child.

### Changing the password

```bash
keyben password reset --projectName myapp \
  --password 'current-password' --new-password 'new-password'
```

Either password can be omitted and will be prompted for securely. Because values are encrypted under the project DEK rather than the password itself, the reset re-derives keys and re-wraps that same DEK, leaving stored ciphertext untouched. A wrong current password is rejected by the server. `KEYBEN_NEW_PASSWORD` works for automation.

A `.keyben.toml` in the working directory keeps the old password until you rebuild it with `keyben config init`.

### Self-signed certificates

```bash
keyben --insecure secrets get --projectName myapp --env dev --name DB_URL
```

`--insecure` skips certificate verification. Use it only when the certificate is self-signed and you control the path. Installing a trusted CA certificate is better.

### Details worth knowing

- Project names are trimmed on every path, so `myapp` and `' myapp '` are the same project rather than two that silently diverge.
- Project creation is exclusive. Once a name is taken, `init` on that name is rejected and existing values are untouched.
- Environments are `dev` and `prod`, and that is the whole list.
- In CI, inject `KEYBEN_PASSWORD` through the runner's protected secret store. Keep passwords, tokens, and plaintext values out of scripts and committed files.

---

## Storage format

The current format is v2: Argon2id key derivation with envelope encryption. It cannot read databases or `.keyben.toml` files written by v0.1.x, and there is no migration path. To move up, start the server on a fresh database path, run `keyben init` again for each project, re-enter the values, and rebuild any project-local file with `keyben config init`.

## License

MIT. See [LICENSE](LICENSE).
