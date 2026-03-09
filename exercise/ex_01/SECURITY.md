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
