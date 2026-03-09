# Security Audit & Hardening

## 1. Container Security Checklist

* **Runs as non-root user**: Addressed. The Dockerfile uses the `nonroot` user provided by the distroless base image. If an attacker exploits a vulnerability in the Go application, they will not have root privileges inside the container, preventing them from easily modifying system files or installing malicious packages.
* **Uses a minimal/distroless base image in the final stage**: Addressed. The final stage uses `gcr.io/distroless/static-debian12`. This matters because distroless images contain no shell or package managers. An attacker cannot use standard tools like `bash`, `curl`, or `wget` to download payloads or explore the system.
* **No secrets baked into the image or layers**: Addressed. Passwords and configurations are passed at runtime via `docker-compose.yaml` environment variables, not hardcoded in the `Dockerfile` or source code. Baking secrets into the image allows anyone who pulls the image to extract the credentials.
* **Base image and dependencies are version-pinned**: Addressed. The build stage uses `golang:1.22-alpine` and the final stage uses `gcr.io/distroless/static-debian12:nonroot`, avoiding `latest`. Using `latest` can lead to unpredictable builds and might inadvertently pull in a newly compromised or vulnerable image version.
* **Uses .dockerignore to exclude sensitive files**: Addressed (assuming `.dockerignore` is created). Excluding files like `.env` or `.git` prevents accidentally copying local secrets or entire repository histories into the container image, which an attacker could otherwise extract.
* **Multi-stage build doesn't leak build tools**: Addressed. The build tools (Go compiler, source files) are left behind in the `builder` stage. The final image only contains the compiled binary. This drastically reduces the attack surface by removing compilers that attackers could use to build exploits from source.

## 2. Attack Surface Analysis

* **Minimal capabilities**: The container only needs the `NET_BIND_SERVICE` capability to bind to a port, though running on a port > 1024 (like 8080) means we don't even need that. In production, we should drop all capabilities by adding `cap_drop: - ALL` to the compose file.
* **Attacker access & limitations**: If an attacker gains code execution, they can access the local filesystem (which is mostly empty due to the distroless image), the network connection to the database, and the environment variables. Their movement is strictly limited by the lack of a shell, lack of system tools (no `curl` or `apt`), and the `nonroot` user permissions.
* **Database password risks**: Passing the password as a plaintext environment variable means it can be viewed by anyone with access to the docker daemon (e.g., via `docker inspect`) or read by a compromised application process dumping the environment. Better alternatives include using Docker Secrets, a dedicated secrets manager (like HashiCorp Vault or AWS Secrets Manager), or passing the secret via mounted, restricted files at runtime.

## 3. Find the Vulnerabilities (insecure-Dockerfile)

[Note: The 'insecure-Dockerfile' was not provided in the prompt. Vulnerability analysis goes here once the file is available.]

## Part C: Docker Bake Multi-platform Builds

Multi-platform builds matter for supply chain security because building for a single architecture (e.g., AMD64) and forcing it to run on another (e.g., ARM64 via emulation) can introduce subtle bugs, performance degradation, and unexpected behaviors that attackers might exploit. Furthermore, explicitly building for multiple platforms ensures that the entire toolchain and dependency tree are verified and tested for the target architecture, preventing malicious packages that might only target specific, less-tested architectures.
