# Security Audit & Hardening

## 1. Container Security Checklist

* **Runs as non-root user**: Addressed. The Dockerfile uses the `nonroot` user provided by the distroless base image. If an attacker exploits a vulnerability in the Go application, they will not have root privileges inside the container, preventing them from easily modifying system files or installing malicious packages.
* **Uses a minimal/distroless base image in the final stage**: Addressed. The final stage uses `gcr.io/distroless/static-debian12`. This matters because distroless images contain no shell or package managers. An attacker cannot use standard tools like `bash`, `curl`, or `wget` to download payloads or explore the system.
* **No secrets baked into the image or layers**: Addressed. Passwords and configurations are passed at runtime via `docker-compose.yaml` environment variables, not hardcoded in the `Dockerfile` or source code. Baking secrets into the image allows anyone who pulls the image to extract the credentials.
* **Base image and dependencies are version-pinned**: Addressed. The build stage uses `golang:1.24-alpine` and the final stage uses `gcr.io/distroless/static-debian12:nonroot`, avoiding `latest`. Using `latest` can lead to unpredictable builds and might inadvertently pull in a newly compromised or vulnerable image version.
* **Uses .dockerignore to exclude sensitive files**: Addressed (assuming `.dockerignore` is created). Excluding files like `.env` or `.git` prevents accidentally copying local secrets or entire repository histories into the container image, which an attacker could otherwise extract.
* **Multi-stage build doesn't leak build tools**: Addressed. The build tools (Go compiler, source files) are left behind in the `builder` stage. The final image only contains the compiled binary. This drastically reduces the attack surface by removing compilers that attackers could use to build exploits from source.

## 2. Attack Surface Analysis

* **Minimal capabilities**: The container only needs the `NET_BIND_SERVICE` capability to bind to a port, though running on a port > 1024 (like 8080) means we don't even need that. In production, we should drop all capabilities by adding `cap_drop: - ALL` to the compose file.
* **Attacker access & limitations**: If an attacker gains code execution, they can access the local filesystem (which is mostly empty due to the distroless image), the network connection to the database, and the environment variables. Their movement is strictly limited by the lack of a shell, lack of system tools (no `curl` or `apt`), and the `nonroot` user permissions.
* **Database password risks**: Passing the password as a plaintext environment variable means it can be viewed by anyone with access to the docker daemon (e.g., via `docker inspect`) or read by a compromised application process dumping the environment. Better alternatives include using Docker Secrets, a dedicated secrets manager (like HashiCorp Vault or AWS Secrets Manager), or passing the secret via mounted, restricted files at runtime.

## 3. Find the Vulnerabilities (insecure-Dockerfile)

* **Using the `latest` tag (`FROM golang:latest`)**: 
    * *What it enables:* This introduces a severe supply chain vulnerability. Because `latest` is unpredictable, it can silently pull in a new image version that contains unpatched vulnerabilities. Furthermore, `golang:latest` is a massive "fat" image containing a full Debian-based OS. This gives an attacker a massive attack surface with countless system libraries to potentially exploit.
* **Running as Root (Missing `USER` directive)**: 
    * *What it enables:* By default, Docker containers run as the `root` user. If an attacker finds a Remote Code Execution (RCE) vulnerability in the Go application, they will execute commands as `root` inside the container. This makes it significantly easier for them to modify system files, install malware, or attempt a container breakout to compromise the underlying host system.
* **Single-Stage Build (Leaving build tools in the image)**: 
    * *What it enables:* By compiling the app and running it in the same stage, the Go compiler, package manager, and original source code are left inside the production image. If an attacker compromises the container, they can use these tools to write, compile, and execute custom C or Go malware directly on the compromised system.
* **Installing Debugging Tools (`apt-get install curl wget netcat vim`)**: 
    * *What it enables:* These are perfect "Living off the Land" tools for an attacker. If they gain command execution, `wget` or `curl` enables them to easily download malicious payloads from the internet. `netcat` enables them to instantly establish a reverse shell back to their own servers. `vim` allows them to easily alter configuration files to maintain persistence.
* **Hardcoded Secrets (`ENV DB_PASSWORD=supersecretpassword123`)**: 
    * *What it enables:* Environment variables defined in a Dockerfile are permanently baked into the image layers. Anyone who can pull the image from the registry (or access the tarball) can simply run `docker inspect <image_name>` or extract the layers to read the database password in plaintext, enabling them to gain unauthorized access to the database.
* **Exposing Port 22 (`EXPOSE 22`)**: 
    * *What it enables:* Port 22 is the standard port for SSH. Containers should run a single application process (the Go API). Exposing port 22 suggests an SSH daemon might be running (or intended to run), which provides attackers with a direct entry point to attempt brute-force login attacks or exploit SSH vulnerabilities. 
* **Indiscriminate Copying (`COPY . .` without explicit `.dockerignore` context)**:
    * *What it enables:* While a `.dockerignore` might exist locally, using `COPY . .` is risky. If sensitive files (like `.env` files containing local developer passwords, `.git` history, or SSH keys) are in the build context, they get copied directly into the image layer. An attacker can extract the image and steal these credentials to pivot to other systems or source code repositories.

## Part C: Docker Bake Multi-platform Builds

Multi-platform builds matter for supply chain security because building for a single architecture (e.g., AMD64) and forcing it to run on another (e.g., ARM64 via emulation) can introduce subtle bugs, performance degradation, and unexpected behaviors that attackers might exploit. Furthermore, explicitly building for multiple platforms ensures that the entire toolchain and dependency tree are verified and tested for the target architecture, preventing malicious packages that might only target specific, less-tested architectures.

---

# Exercise 2 — Supply Chain Security Analysis

## 1. Dependency Trust Audit (4p)

### Complete Third-Party Action Inventory

The CI/CD pipeline uses the following third-party GitHub Actions:

| Action | Pinning | Maintainer | Verified Org? |
|---|---|---|---|
| `actions/checkout` | **SHA-pinned** → `@11bd71901bbe5b1630ceea73d27597364c9af683` (v4.2.2) | GitHub (Official) | ✅ Yes |
| `actions/setup-go` | Tag `@v5` | GitHub (Official) | ✅ Yes |
| `actions/upload-artifact` | Tag `@v4` | GitHub (Official) | ✅ Yes |
| `actions/download-artifact` | Tag `@v4` | GitHub (Official) | ✅ Yes |
| `golangci/golangci-lint-action` | Tag `@v6` | golangci (Community) | ⚠️ No (widely adopted, but not GitHub-verified) |
| `hadolint/hadolint-action` | Tag `@v3.1.0` | Hadolint (Community) | ⚠️ No |
| `docker/setup-qemu-action` | Tag `@v3` | Docker (Official) | ✅ Yes |
| `docker/setup-buildx-action` | Tag `@v3` | Docker (Official) | ✅ Yes |
| `docker/login-action` | Tag `@v3` | Docker (Official) | ✅ Yes |
| `docker/metadata-action` | Tag `@v5` | Docker (Official) | ✅ Yes |
| `docker/build-push-action` | Tag `@v6` | Docker (Official) | ✅ Yes |
| `aquasecurity/trivy-action` | **SHA-pinned** → `@18f2510ee396bbf400402947e0f18c1397d4e843` (v0.28.0) | Aqua Security (Community) | ⚠️ No (widely trusted in security space) |
| `github/codeql-action` | Tag `@v3` | GitHub (Official) | ✅ Yes |
| `sigstore/cosign-installer` | Tag `@v3` | Sigstore / Linux Foundation | ✅ Yes |

### Risk of Tag-Based Pinning (`@v3`)

Most of our actions use mutable version tags like `@v3` or `@v6`. This is convenient because Dependabot can auto-update them, but it is dangerous because a tag is simply a Git pointer that can be moved at any time. If an attacker compromises a maintainer's account, they can force-push malicious code to an existing tag, and every workflow referencing that tag will silently execute the compromised version on its next run.

**Real-world precedent — the `tj-actions/changed-files` incident (March 2025):** An attacker compromised the `tj-actions/changed-files` action by rewriting its mutable tags. Every CI pipeline referencing `@v35` (or similar) began running attacker-controlled code that exfiltrated CI secrets (including `GITHUB_TOKEN` and any custom secrets) by dumping them to workflow logs. Because the attack used the *same tag*, no version bump appeared in the workflow file — the change was completely invisible to repository owners.

Similarly, there have been ongoing supply chain discussions around `actions/checkout` itself, highlighting that even official actions could theoretically be targeted. The `reviewdog/action-setup` compromise in March 2025 followed the same pattern.

### SHA-Pinned Actions in This Pipeline

We SHA-pinned the **two most security-critical actions** in our pipeline:

1. **`actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683`** (instead of `@v4`)
   * *Why:* This is the most critical action — it runs first in every job and has access to our repository contents and `GITHUB_TOKEN`. A compromised checkout action could silently inject malicious code into every subsequent step. By pinning to the exact commit SHA, we ensure that even if the `v4` tag is moved, our pipeline will continue using the audited version. Since checkout is used in 4 out of 5 jobs, a compromise here would have maximum blast radius.

2. **`aquasecurity/trivy-action@18f2510ee396bbf400402947e0f18c1397d4e843`** (instead of `@v0.28.0`)
   * *Why:* Trivy runs with access to our built Docker image and has `security-events: write` permission. A compromised Trivy action could exfiltrate the image contents (which may contain compiled application secrets or proprietary code), report false "clean" results to hide vulnerabilities, or tamper with our GitHub Security tab. SHA-pinning is especially important for security tooling — the very tools we trust to find problems must themselves be trustworthy. Additionally, as a community-maintained (not GitHub-verified) action, Trivy carries higher supply chain risk than the official Docker or GitHub actions.

---

## 2. Secrets Management (4p)

### Secrets Inventory and Minimum Permissions

| Secret | Purpose | Minimum Required Permissions |
|---|---|---|
| `GITHUB_TOKEN` (automatic) | Push images to GHCR, upload SARIF | `packages:write`, `security-events:write`, `contents:read` |
| `GITHUB_TOKEN` (for cosign) | Keyless signing with Sigstore OIDC | `id-token:write` (to request OIDC token from GitHub) |

Our pipeline intentionally avoids custom secrets. We use `GITHUB_TOKEN` exclusively, which is automatically provisioned by GitHub Actions with scoped, short-lived permissions.

### Blast Radius of a Leaked `DOCKER_TOKEN`

If a `DOCKER_TOKEN` (e.g., Docker Hub PAT or GHCR token) were leaked from a CI log, the attacker could:

* **Push malicious images** to the registry under our repository's namespace, potentially deploying backdoored containers to anyone pulling our image (including production systems with auto-pull).
* **Overwrite existing tags** (e.g., `latest`) with a compromised image — a supply chain attack on all downstream consumers.
* **Pull private images** from the registry, potentially accessing proprietary application code.
* **Pivot laterally** if the token has broader scopes (e.g., a Docker Hub PAT with `admin` scope could delete repositories or modify organization settings).

**Mitigation strategies:**
* Use `GITHUB_TOKEN` instead of personal tokens — it is automatically scoped to the repository and expires when the workflow run completes (short-lived).
* Set `permissions:` blocks with least-privilege per job (as we do in our pipeline), so even the automatic token only has the capabilities it needs.
* Enable Docker Hub or GHCR access tokens with the narrowest scope possible (read-only for pull, write for push to a specific repo only).
* Use `docker/login-action` which handles credentials securely via stdin, never echoing them to logs.
* Enable audit logging on the container registry to detect unauthorized pushes.
* Rotate tokens immediately upon suspicion of compromise and re-tag/re-sign all affected images.

### `GITHUB_TOKEN` vs. Personal Access Token (PAT)

Our pipeline uses `${{ secrets.GITHUB_TOKEN }}` instead of a PAT for these security reasons:

* **Automatically scoped:** `GITHUB_TOKEN` is automatically limited to the repository that triggers the workflow. A PAT, by contrast, typically grants access to *all* repositories the user can access, massively increasing the blast radius of a leak.
* **Short-lived:** `GITHUB_TOKEN` expires when the workflow run finishes. A PAT is long-lived (up to indefinite for classic PATs) and remains valid until manually revoked.
* **No human secret management:** `GITHUB_TOKEN` is provisioned automatically — no one needs to create, store, rotate, or share it. PATs must be manually created and stored as repository secrets, creating opportunities for mishandling.
* **Auditable permissions:** With the `permissions:` block, we can restrict `GITHUB_TOKEN` to the exact scopes needed per job. PAT scopes are set at creation time and apply globally to every API call made with the token.
* **Revocation on settings change:** If repository settings or branch protections change, `GITHUB_TOKEN` permissions update automatically. PATs retain their original scopes regardless.

### Detecting Secret Exfiltration via Malicious PRs

A malicious PR could attempt to exfiltrate secrets by modifying the workflow file or injecting code that prints secrets to logs, sends them to an external server, or encodes them in artifact names. Detection and prevention measures:

* **Require environment approval:** Our pipeline uses `environment: production` on the push job. GitHub environments can require manual approval from designated reviewers before running, preventing fork PRs from automatically executing privileged jobs.
* **Use `pull_request` (not `pull_request_target`):** The `pull_request` event runs the workflow from the *fork's* code but with a read-only `GITHUB_TOKEN` and no access to repository secrets. This is our default for PR builds.
* **Branch protection rules:** Require PR reviews before merging to `main`. Any workflow file changes (`.github/workflows/`) should trigger mandatory review from a CODEOWNERS-designated security reviewer.
* **GitHub's secret masking:** GitHub Actions automatically masks any value registered as a secret in log output. However, attackers can bypass this with encoding (base64, hex, reversed strings), so masking alone is not sufficient.
* **Monitor workflow runs:** Audit the Actions tab for unexpected network calls, unusually long runtimes, or workflows triggered by unknown contributors. GitHub's audit log records every workflow run and its triggering event.
* **Use OpenSSF Scorecard or StepSecurity Harden-Runner:** Tools like `step-security/harden-runner` can monitor network egress during workflow execution and alert on unexpected outbound connections (e.g., a step trying to send data to an unknown IP).

---

## 3. Pipeline Hardening (4p)

We implemented the following three hardening measures:

### 3.1 Least-Privilege `permissions` Blocks per Job

**Implementation:** Every job in the pipeline declares an explicit `permissions:` block with only the scopes it needs. The top-level workflow sets `permissions: {}` (deny-all), and each job opts in to specific permissions:

* `lint`: `contents: read` only
* `build`: `contents: read` + `packages: write`
* `security-scan`: `contents: read` + `security-events: write`
* `integration-test`: `contents: read` only
* `push`: `contents: read` + `packages: write` + `id-token: write`

**Why this matters:** By default, `GITHUB_TOKEN` has broad read/write permissions. If a compromised action (e.g., a supply chain attack on a linting tool) tries to push code or modify packages, it will be blocked because the lint job's token only has `contents: read`. This limits the blast radius of any single compromised step.

### 3.2 Image Signing with Cosign (SLSA Provenance)

**Implementation:** After pushing the multi-platform image to GHCR, the pipeline uses `sigstore/cosign-installer` and runs `cosign sign --yes` with keyless signing. Cosign uses GitHub's OIDC identity provider to generate a short-lived certificate, binding the image signature to the specific workflow run, commit SHA, and repository.

**Why this matters:** Without image signing, an attacker who gains write access to the registry can replace our image with a malicious one, and consumers have no way to verify authenticity. With cosign signatures, anyone pulling our image can run `cosign verify` to cryptographically confirm that: (a) the image was built by *our* CI pipeline, (b) from a specific commit, (c) on a specific date. This is a foundational step toward SLSA Level 2+ compliance.

### 3.3 Fork Protection via GitHub Environment

**Implementation:** The `push` job (which has registry write access and signing capabilities) uses `environment: production`. This GitHub environment can be configured to:
* Require manual approval from designated reviewers before the job runs.
* Restrict which branches can deploy to the environment (e.g., only `main`).
* Add a wait timer for additional review time.

**Why this matters:** Without environment protection, a sophisticated attacker could: (a) fork the repository, (b) modify the workflow to exfiltrate secrets, (c) open a PR that triggers the workflow with elevated privileges. The `environment: production` gate ensures a human must approve before any privileged operation executes. Combined with using `pull_request` (not `pull_request_target`), fork PRs never get access to secrets in the first place.
