# SECURITY.md — Recipe API Security Audit

---

## Part B.1 — Container Security Checklist

### ✅ Runs as non-root user
**Addressed:** Yes. The final stage uses `gcr.io/distroless/static-debian12:nonroot`, which runs as the `nonroot` user (UID 65532) by default. The `USER nonroot:nonroot` directive in the Dockerfile makes this explicit and intentional.

**Why it matters:** Docker containers run as root (UID 0) by default. If an attacker exploits a vulnerability in the recipe API (e.g. via a crafted recipe payload or a dependency bug in Gin or GORM), running as root inside the container gives them far greater power — they can read and write any file, and container escape exploits are significantly easier to execute as root. A non-root user limits the blast radius of any successful exploit.

---

### ✅ Uses a minimal/distroless base image in the final stage
**Addressed:** Yes. The production stage uses `gcr.io/distroless/static-debian12:nonroot` — it contains only the compiled binary and the absolute minimum system libraries. There is no shell (`sh`, `bash`), no package manager (`apt`, `apk`), no `curl`, no `wget`, no `netcat`.

**Why it matters:** Every tool present in a container is a potential weapon for an attacker. With a full Alpine or Ubuntu base, an attacker who gets code execution can use the shell to run commands, use `curl` to download further malware, or use `wget` to exfiltrate data. Distroless eliminates all of this — even with code execution, the attacker has almost nothing available to them inside the container.

---

### ✅ No secrets baked into the image or layers
**Addressed:** Yes. The Dockerfile contains no `ENV` instructions with secret values. All credentials (`DB_USER`, `DB_PASSWORD`, `DB_NAME`) are passed at runtime via a `.env` file read by Docker Compose. The `.env` file itself is excluded from the image via `.dockerignore`.

**Why it matters:** Docker image layers are permanent and inspectable. If a secret were set via `ENV DB_PASSWORD=secret` in the Dockerfile, it would be baked into every layer of the image — visible to anyone running `docker inspect`, to anyone who pulls the image from a registry, and retrievable from intermediate layers even if overwritten later. Runtime injection means secrets never touch the image at all. This is especially important for this app because `serve.go` reads credentials via Viper from environment variables — they only need to exist at runtime, never at build time.

---

### ✅ Base image and dependencies are version-pinned (no `latest` tags)
**Addressed:** Yes. All images use pinned versions:
- `golang:1.24-alpine` — matches the `go 1.24` declaration in `go.mod`
- `gcr.io/distroless/static-debian12:nonroot` — pinned to debian12
- `postgres:16.2-alpine` — explicit patch version

Go module dependencies are also fully pinned via `go.sum`, which cryptographically locks every dependency to a specific version and hash.

**Why it matters:** `latest` is a moving target. A new upstream release could introduce a vulnerability, a breaking change, or — in a supply chain attack — malicious code pushed by a compromised maintainer. Pinned versions mean builds are reproducible and auditable: you know exactly what you're running and can verify it against known CVEs.

---

### ✅ Uses `.dockerignore` to exclude sensitive files
**Addressed:** Yes. The `.dockerignore` excludes:
- `.env` and `*.env` — contain database credentials
- `.git/` — contains full commit history, which may include old secrets or sensitive config
- `*.pem`, `*.key`, `*.crt` — private keys and certificates
- `src/main` — the pre-built binary that already exists in the repo (we build fresh inside Docker)

**Why it matters:** `COPY src/ .` copies everything in the build context unless explicitly excluded. Without `.dockerignore`, the `.env` file with the database password, the git history, and any private keys would all be baked into the builder stage image layer. Anyone who accesses that image gets all of it. The pre-built `src/main` binary is also excluded because its provenance is unknown — we want to build from source, not ship an arbitrary binary.

---

### ✅ Multi-stage build doesn't leak build tools into production image
**Addressed:** Yes. The Dockerfile uses two stages:
1. **builder** (`golang:1.24-alpine`) — has the Go compiler, `git`, and all build tooling. Downloads all dependencies from `go.sum` and compiles the binary.
2. **production** (`distroless/static-debian12:nonroot`) — receives only the compiled `/recipe-api` binary via `COPY --from=builder`.

The final image contains zero Go tooling, no Alpine package manager, no `git`, no compiler. The entire `golang:1.24-alpine` layer is discarded after the build stage.

**Why it matters:** Build tools dramatically increase attack surface in production. The Go compiler could be used to compile new attack tools inside the container. `git` could clone malicious repos. `apk` could install anything. Multi-stage builds ensure none of these survive into the image that actually runs. The production image is as small and minimal as possible.

---

## Part B.2 — Attack Surface Analysis

### Minimal capabilities needed
The recipe API is a simple HTTP server on port 8080 that talks to PostgreSQL. The minimal Linux capabilities it needs are effectively **none beyond the kernel defaults**. Specifically:

- **Does not need `NET_ADMIN`** — it opens a listening socket on port 8080 (above 1024, no special capability needed for non-root) but does no network configuration
- **Does not need `SYS_ADMIN`** — no system administration operations
- **Does not need `CHOWN`, `SETUID`, `SETGID`** — already running as non-root, no privilege changes needed
- **Does not need `DAC_OVERRIDE`** — no need to bypass file permission checks

In production, all capabilities should be explicitly dropped:
```yaml
# in docker-compose.yaml
cap_drop:
  - ALL
```
And a read-only root filesystem should be enforced:
```yaml
read_only: true
```
This follows the principle of least privilege — the process has only exactly what it needs to serve HTTP and connect to PostgreSQL.

---

### If an attacker gains code execution inside the container
**What they can access:**
- The `/recipe-api` binary itself
- Environment variables in the process environment — including `DB_PASSWORD`, `DB_USER`, and `DB_NAME` passed by Docker Compose. These are readable by any process running as the same user.
- The PostgreSQL database, since the app holds valid credentials and has network access to the `db` container on the internal Docker network
- Other containers on the same Docker Compose network, reachable by service name (e.g. `db:5432`)
- The `/health`, `/debug`, `/recipes`, and all other endpoints — the `/debug` endpoint in particular reflects request headers back to the caller, which could be useful for an internal attacker probing the network

**What limits their movement:**
- **No shell** — distroless has no `sh` or `bash`. Standard shell-based post-exploitation techniques don't work.
- **No network tools** — no `curl`, `wget`, `netcat`. Downloading additional tools or exfiltrating data over HTTP is very difficult without these.
- **Non-root user** — cannot write to most of the filesystem, cannot install packages, cannot bind to privileged ports.
- **No package manager** — cannot install anything at all.
- **Ports bound to localhost only** (`127.0.0.1:8080`) — the container is not directly reachable from external networks; traffic must go through the host.
- **Internal Docker network isolation** — the `db` container is only reachable from within the compose network, not from outside.

The main remaining risk is **lateral movement to the database** — the app holds valid PostgreSQL credentials and can execute arbitrary SQL via GORM. This is why database-level access controls matter as a second layer of defense (e.g. the DB user should only have SELECT/INSERT/UPDATE/DELETE on the recipes table, not SUPERUSER or the ability to read `pg_shadow`).

---

### Database password as environment variable — risks and alternatives

**Risks of environment variables:**
- They are readable by any process running as the same UID inside the container — including the app itself if it logs its environment accidentally
- They appear in `docker inspect` output on the host
- In orchestrated environments (Kubernetes), they can appear in pod specs stored in etcd, which may not be encrypted at rest by default
- If the app panics and produces a crash dump, environment variables may be included
- The `serve.go` code uses Viper, which reads env vars — if debug logging were ever enabled, credentials could leak into logs

**Alternatives (discussion only):**

1. **Docker Secrets (Docker Swarm)** — Secrets are mounted as files at `/run/secrets/<name>` inside the container. They are encrypted at rest and in transit, never appear in `docker inspect`, and are only available to services explicitly granted access. The app would read the file instead of an env var. Not available in plain Docker Compose without Swarm mode.

2. **HashiCorp Vault** — A dedicated secrets management system. The app authenticates to Vault at startup using a token or cloud identity and retrieves short-lived credentials dynamically. Credentials can be rotated automatically and expire after a configurable TTL. This is the gold standard for production secrets management.

3. **Cloud provider secret managers** — AWS Secrets Manager, GCP Secret Manager, or Azure Key Vault. The app retrieves secrets via API at runtime using its cloud IAM identity (no static credentials required). Secrets are versioned, auditable, and can be rotated without redeploying the container.

4. **Mounted secret files** — Pass the password as a file mounted into the container (`/run/secrets/db_password`) rather than an env var. The app reads the file at startup. Slightly safer than env vars since secret files don't appear in `docker inspect` environment listings and are not inherited by child processes.

---

## Part B.3 — Vulnerabilities in `insecure-Dockerfile`

### Issue 1: `FROM golang:latest` — Unpinned base image
**Risk: Medium-High**
`latest` changes silently with every new Go release. A compromised or buggy upstream release is automatically pulled in on the next build. You lose reproducibility — you cannot guarantee that what you built yesterday is the same as what you build today. In a supply chain attack scenario, a malicious actor who gains access to the upstream image could push a backdoored `latest` tag that gets silently adopted by every project using it.

---

### Issue 2: Single-stage build — Full Go toolchain in production
**Risk: Medium**
The entire `golang:latest` image ends up in production. This is hundreds of megabytes containing a full Linux userland, the Go compiler, `git`, `apt`, and a shell. Every one of these is a tool an attacker can use after gaining entry. The Go compiler alone could be used to compile new attack binaries inside the container.

---

### Issue 3: `RUN apt-get install curl wget netcat vim` — Dangerous tooling installed
**Risk: High**
These are standard post-exploitation tools:
- `curl` / `wget` — download malware from external servers, exfiltrate data
- `netcat` — open reverse shells, act as a backdoor, transfer files between systems
- `vim` — edit system files, crontabs, or startup scripts to persist access

Installing these "for convenience" in a production image directly hands an attacker a working toolkit.

---

### Issue 4: `ENV DB_PASSWORD=supersecretpassword123` — Secret hardcoded in image
**Risk: Critical**
This bakes the database password permanently into the image as a layer. It is visible via `docker inspect`, visible to anyone who pulls the image from any registry it's pushed to, and stored forever in the image layer history. Even if a later `ENV` or `RUN` command overwrites it, the original value remains readable in the lower layer. For this recipe API specifically, this would give an attacker direct access to the PostgreSQL database containing all recipe data.

---

### Issue 5: `ENV DB_USER=admin` — Privileged DB username revealed
**Risk: Medium**
Using `admin` as the database username suggests a highly privileged account. Combined with the exposed password above, this gives an attacker full administrative database access — not just read access to recipes, but potentially the ability to drop tables, read system catalogs like `pg_shadow`, or create new superuser accounts.

---

### Issue 6: `EXPOSE 22` — SSH port exposed
**Risk: High**
Port 22 is SSH. A containerized API has no legitimate reason to expose SSH. This implies an SSH server is running inside the container, which is a major attack surface — vulnerable to brute force attacks, key theft, and provides an attacker with a direct interactive shell if compromised. It also signals that the container was designed to be accessed directly rather than through proper orchestration tooling.

---

### Issue 7: No non-root user — Running as root by default
**Risk: Critical**
Without a `USER` directive, the container runs as root (UID 0). If an attacker exploits the recipe API (e.g. via a vulnerability in Gin, GORM, or the `lib/pq` driver), they immediately have root access inside the container. Container escape attacks — techniques to break out of the container namespace and access the host — are significantly more powerful and more likely to succeed when the attacker already has root inside the container.

---

### Issue 8: `COPY . .` without `.dockerignore` — Leaking sensitive files into image
**Risk: High**
Without `.dockerignore`, every file in the project directory is copied into the image, including `.env` files with database credentials, the `.git/` directory with full commit history (which may contain old secrets, internal URLs, or configuration), any private keys or certificates, and the pre-built `src/main` binary of unknown provenance. Anyone who pulls the image from a registry receives all of this.

---

## Part C — Docker Bake & Multi-Platform Security

See `docker-bake.hcl` for the bake configuration.

To build and push both platforms:
```bash
docker buildx create --use
docker buildx bake --push
```

### Why multi-platform builds matter for supply chain security

**The problem with single-architecture builds:**
If you build only for `linux/amd64` but deploy on an `arm64` machine (AWS Graviton instances, Apple Silicon, Raspberry Pi clusters), Docker will attempt to run the image under QEMU emulation. This has several security implications:

1. **Emulation introduces additional attack surface** — QEMU is a large, complex piece of software with its own vulnerability history. Running production workloads through an emulation layer means you're trusting an additional software component that isn't part of your audited stack.

2. **You lose binary verification guarantees** — If Docker silently pulls an `arm64` image variant that you didn't build or audit, you cannot verify that it was compiled from the same source code with the same flags. A compromised registry could serve a malicious `arm64` variant while the `amd64` variant passes all your security scans and tests.

3. **Supply chain integrity** — Building both architectures yourself from the same Dockerfile and the same audited source code means you control the entire build pipeline for both platforms. You're not trusting a third party to have built a correct and unmodified arm64 variant. Using `docker buildx` with `--sbom` and `--provenance` flags attaches a cryptographically signed Software Bill of Materials (SBOM) to each platform variant, allowing downstream consumers to verify what went into the image.

4. **Reproducibility and auditability** — The `docker-bake.hcl` file declaratively defines targets, platforms, and build arguments in a version-controlled file. Every CI/CD run uses the same bake file, making builds reproducible and the build configuration auditable — a core requirement of modern supply chain security standards like SLSA.
