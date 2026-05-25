# Exercise 5: ArgoCD & GitOps — SECURITY.md

## Authors: Jonathan Rusche & Mikolaj Milczek

---

# Part A: ArgoCD Setup & Application Deployment

## A1. ArgoCD Installation

### Installation Method

ArgoCD was installed using the official plain manifests into a dedicated `argocd` namespace:

```bash
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

We chose plain manifests over Helm or the Operator because they provide a transparent, auditable installation — every resource is visible in a single YAML file, and there is no abstraction layer obscuring what is being deployed. For a learning environment this makes it easier to understand exactly what ArgoCD installs (CRDs, Deployments, Services, RBAC, etc.).

### Why should ArgoCD run in its own dedicated namespace?

ArgoCD must run in its own namespace (typically `argocd`) for several security reasons:

1. **Blast-radius isolation.** ArgoCD's service accounts have extremely powerful permissions — they can create, modify, and delete resources across the entire cluster. If ArgoCD shared a namespace with application workloads, a compromised application pod could potentially access ArgoCD's service account tokens (via mounted secrets or the Kubernetes API), gaining cluster-wide control.

2. **RBAC boundary.** Kubernetes RBAC policies are scoped by namespace. Placing ArgoCD in its own namespace allows administrators to restrict who can `exec` into ArgoCD pods, read its secrets, or view its ConfigMaps — without those restrictions affecting application namespaces.

3. **Network policy isolation.** With a dedicated namespace, network policies can tightly control ingress/egress for ArgoCD components (e.g., only the API server should be reachable from outside, the repo-server should only talk to Git endpoints and the application controller).

4. **Audit clarity.** Kubernetes audit logs include the namespace of every API request. A dedicated namespace makes it trivial to filter and monitor all ArgoCD-related activity separately from application operations.

### Default admin password — generation and storage

When ArgoCD is first installed, the initial admin password is set to the **name of the ArgoCD API server pod** (e.g., `argocd-server-abc123def`). This value is stored as a bcrypt hash in the Kubernetes Secret `argocd-initial-admin-secret` in the `argocd` namespace.

**Why it must be changed immediately:**

- The pod name is predictable and discoverable by anyone with `kubectl get pods -n argocd` access.
- The initial secret is stored in a well-known location (`argocd-initial-admin-secret`) that any attacker who gains namespace-level read access can retrieve.
- The admin account has full ArgoCD access — it can create/delete applications, modify RBAC, add repositories, and effectively control what runs in the entire cluster.
- After changing the password, the `argocd-initial-admin-secret` should be deleted: `kubectl delete secret argocd-initial-admin-secret -n argocd`.

```bash
# Change the admin password:
argocd account update-password --account admin --current-password <pod-name> --new-password <strong-password>

# Then delete the initial secret:
kubectl delete secret argocd-initial-admin-secret -n argocd
```

---

## A2. App-of-Apps Pattern

### What is the App-of-Apps pattern?

The App-of-Apps pattern is an ArgoCD design where a single **root Application** resource points to a Git directory containing other **Application** manifests (child applications). When ArgoCD syncs the root application, it discovers and creates the child Application resources, which in turn deploy the actual workloads.

In our setup:
- **Root Application** (`argocd/root-app.yaml`): Points to the `applications/` directory in our Git repository.
- **Child Application** (`applications/recipe-api.yaml`): Deploys the recipe API using the Helm chart from Exercise 4.

### Why is App-of-Apps preferred over manual creation?

1. **Declarative management.** Instead of running `argocd app create ...` imperatively (which leaves no audit trail and is not reproducible), every application definition exists as a YAML file in Git. This means the set of deployed applications is version-controlled, reviewable, and reproducible.

2. **Self-bootstrapping.** A new cluster only needs the root application to be applied manually. Everything else (all child applications, their configurations, sync policies) is automatically created from Git. This enables disaster recovery: if the cluster is lost, re-applying the root app rebuilds the entire deployment.

3. **Scalability.** Adding a new application to the cluster is a `git commit` — add a new YAML file to `applications/`, push, and ArgoCD automatically creates and syncs it. No manual CLI commands or UI clicks needed.

### Security benefits of managing ArgoCD applications declaratively in Git

- **Audit trail.** Every change to any application configuration (sync policy, target revision, parameters) is a Git commit with an author, timestamp, and (optionally) a GPG signature. This creates a tamper-evident record of who changed what and when.
- **Code review as a security gate.** Changes to deployment configurations go through pull requests, which can require approval from security-designated reviewers before merging. This prevents a single compromised account from silently modifying the deployment pipeline.
- **Drift prevention.** If someone manually creates an ArgoCD application via the CLI or UI, it exists only in the cluster — untracked, unreviewable, and invisible to the team. With App-of-Apps, the root application's `prune: true` policy will **delete** any Application that is not declared in Git, preventing shadow deployments.
- **Reproducibility.** The exact state of the deployment pipeline at any point in time can be reconstructed from Git history. After a security incident, responders can `git diff` to identify exactly what changed and when.

---

## A3. End-to-End Verification

### GitOps Flow Demonstration

To demonstrate the full GitOps loop, we changed the Helm chart and verified ArgoCD automatically synced it.

**Note on demo images:** The original Exercise 4 chart references `vstadtmueller/recipe-api:1.0.0`, which was never published to a public registry, and the chart's `postgresql` subchart references a Bitnami image tag that is no longer hosted publicly. To make the end-to-end demo fully working without modifying the Exercise 4 chart, the **Application manifest** (`applications/recipe-api.yaml`) overrides the image to a real public image (`paulbouwer/hello-kubernetes:1.10.1`) and disables the PostgreSQL subchart via Helm parameters. The chart itself remains unmodified.

**Step 1 — Make a change in Git:**
```powershell
# Bump replicaCount in values-prod.yaml from 3 to 4
# (commit ce46643)
git add exercise/ex_05/recipe-chart/values-prod.yaml
git commit -m "GitOps demo: bump replicaCount 3 -> 4"
git push origin main
```

**Step 2 — ArgoCD detects and syncs (proof: `proof/A3_app_get.txt`):**
```
Source:
- Repo:             git@github.com:Bosssmannn/sdx6ue.git
  Target:           main
  Path:             exercise/ex_05/recipe-chart
  Helm Values:      values.yaml,values-prod.yaml
Sync Status:        Synced to main (ce46643)
Health Status:      Healthy

GROUP              KIND        NAMESPACE   NAME                       STATUS  HEALTH       HOOK  MESSAGE
                   Secret      recipe-api  recipe-api-db-credentials  Synced
                   Service     recipe-api  recipe-api                 Synced  Healthy
apps               Deployment  recipe-api  recipe-api                 Synced  Healthy
networking.k8s.io  Ingress     recipe-api  recipe-api                 Synced  Progressing
```

**Step 3 — Verify sync history (proof: `proof/A3_app_history.txt`):**
```
SOURCE  git@github.com:Bosssmannn/sdx6ue.git
ID      DATE                            REVISION
0       2026-05-25 19:00:14 +0200 CEST  main (f75ac2c)   # Initial sync
1       2026-05-25 19:00:22 +0200 CEST  main (f75ac2c)   # Retry
2       2026-05-25 19:01:55 +0200 CEST  main (8470a43)   # CM fix
3       2026-05-25 19:03:36 +0200 CEST  main (ce46643)   # GitOps demo: 3 -> 4 replicas
```

**Step 4 — Verify in Kubernetes (proof: `proof/A3_kubectl_deployment.txt`):**
```
NAME         READY   UP-TO-DATE   AVAILABLE   AGE
recipe-api   4/4     4            4           3m50s
```

The replica count of **4** matches `replicaCount: 4` in `values-prod.yaml` — proving the Git commit propagated all the way to the running cluster automatically via ArgoCD's auto-sync.

---

# Part B: ArgoCD Security Hardening

## B1. RBAC Configuration

### Roles Defined

We configured ArgoCD RBAC via the `argocd-rbac-cm` ConfigMap (`argocd/argocd-rbac-cm.yaml`):

**Admin role (`role:admin`):**
- Full access to all ArgoCD resources: applications, clusters, repositories, certificates, accounts, GPG keys, logs, and exec.
- Bound to user `admin-user`.

**Developer role (`role:developer`):**
- Can **view** applications (`get`) and **sync** applications (trigger deployments).
- Can view logs.
- **Cannot** delete applications, create/modify repositories, change ArgoCD settings, manage accounts, or access cluster configuration.
- Bound to user `dev-user`.

### Testing RBAC

```bash
# Create the local accounts
kubectl apply -f argocd/argocd-cm.yaml
kubectl apply -f argocd/argocd-rbac-cm.yaml

# Set passwords for the test accounts
argocd account update-password --account dev-user --current-password <admin-pw> --new-password <dev-pw>

argocd login localhost:8080 --username dev-user --password "DevUser123!" --insecure
```

**Actual test results (full transcript: `proof/B1_rbac_tests.txt`):**

```
==== Test 1: dev CAN list apps ====                                              SUCCESS
$ argocd app list
NAME               STATUS  HEALTH       SYNCPOLICY
argocd/recipe-api  Synced  Progressing  Auto-Prune
argocd/root-app    Synced  Healthy      Auto-Prune

==== Test 3: dev CAN sync ====                                                   SUCCESS
$ argocd app sync recipe-api
(returns full sync result, all resources Synced)

==== Test 4: dev CANNOT delete ====                                              BLOCKED
$ argocd app delete recipe-api --yes
FATAL: rpc error: code = PermissionDenied desc = permission denied:
applications, delete, default/recipe-api, sub: dev-user

==== Test 5: dev CANNOT add repositories ====                                    BLOCKED
$ argocd repo add git@github.com:fake/fake.git
FATAL: rpc error: code = PermissionDenied desc = permission denied:
repositories, create, git@github.com:fake/fake.git, sub: dev-user

==== Test 6: dev CANNOT update accounts ====                                     BLOCKED
$ argocd account update-password --account admin --new-password "..."
FATAL: rpc error: code = PermissionDenied desc = permission denied:
accounts, update, admin, sub: dev-user
```

**Conclusion:** The developer role can perform its day-to-day duties (view, sync) but is blocked from any operation that modifies ArgoCD configuration or escalates privileges.

### Why is ArgoCD RBAC important even if Kubernetes RBAC is already configured?

ArgoCD RBAC and Kubernetes RBAC operate at **different layers** and control **different things**:

| Aspect | Kubernetes RBAC | ArgoCD RBAC |
|---|---|---|
| **What it controls** | API server access: who can `kubectl get/create/delete` Kubernetes resources | ArgoCD operations: who can view/sync/delete ArgoCD Applications, add repos, manage settings |
| **Identity source** | Service accounts, certificates, OIDC tokens used with `kubectl` | ArgoCD local accounts or SSO identities used with the ArgoCD UI/CLI |
| **Scope** | Kubernetes resources (Pods, Deployments, Secrets, etc.) | ArgoCD resources (Applications, Projects, Repositories, Clusters) |

**The key distinction:** A developer might have zero Kubernetes RBAC permissions (cannot run `kubectl` at all) but still have ArgoCD access to sync applications — because ArgoCD's own service account performs the Kubernetes API calls on their behalf. ArgoCD RBAC controls *who can tell ArgoCD what to do*, while Kubernetes RBAC controls *what ArgoCD's service account is allowed to do in the cluster*.

Without ArgoCD RBAC:
- Any ArgoCD user could delete critical applications, causing production outages.
- Any user could add a malicious Git repository and deploy arbitrary workloads.
- Any user could modify ArgoCD's own configuration, escalating their own privileges.
- The admin password would be the only protection, shared among all users.

---

## B2. Repository Access Security

### SSH Deploy Key Configuration

ArgoCD was configured to access the Git repository using an SSH deploy key with **read-only** access:

```bash
# Generate an SSH key pair (on a secure workstation)
ssh-keygen -t ed25519 -C "argocd-deploy-key" -f argocd-deploy-key -N ""

# Add the PUBLIC key as a read-only deploy key on GitHub:
# GitHub repo → Settings → Deploy Keys → Add → paste argocd-deploy-key.pub → Do NOT check "Allow write access"

# Add the PRIVATE key to ArgoCD:
argocd repo add git@github.com:<YOUR_USERNAME>/sdx6ue.git \
  --ssh-private-key-path argocd-deploy-key \
  --insecure-ignore-host-key  # Only for initial setup; configure known_hosts properly in production

# Securely delete the local private key after adding to ArgoCD:
# (ArgoCD now stores it as a Kubernetes Secret)
```

### What is the blast radius if ArgoCD repository credentials are compromised?

If the SSH deploy key is compromised, the attacker can:

1. **Clone the entire repository** — accessing all Helm charts, ArgoCD application manifests, Kubernetes configurations, CI/CD workflow definitions, and any secrets that may have been committed (even accidentally in git history).
2. **If the key has write access:** Push malicious changes to the Helm chart (e.g., change the container image to a backdoored one, modify resource limits, inject environment variables). Because ArgoCD auto-syncs from Git, these malicious changes would be automatically deployed to the cluster within minutes — **a direct path from key compromise to production compromise**.
3. **With read-only access (our configuration):** The attacker can read all code and configuration, which may reveal infrastructure details useful for further attacks, but they **cannot modify** what ArgoCD deploys. This dramatically reduces the blast radius — the compromise becomes an information disclosure issue rather than a remote code execution path.

### Why is a read-only deploy key preferable to a PAT with full repo access?

| Property | Read-only SSH Deploy Key | PAT with full repo access |
|---|---|---|
| **Scope** | Single repository, read-only | All repositories the user can access (potentially hundreds) |
| **Write access** | None — attacker cannot push changes | Full — attacker can push to any repo |
| **Identity** | Machine identity — no human account involved | Tied to a human user account — compromising it grants the attacker's full GitHub identity |
| **Blast radius** | Read access to one repo | Read/write access to all repos, plus potential access to GitHub settings, team management, etc. |
| **Revocation** | Revoke one deploy key; no impact on human workflows | Revoke the PAT; may break the user's other tooling, SSH, or API integrations |
| **Least privilege** | Yes — minimal necessary access | No — massively over-privileged for ArgoCD's needs |

A PAT also typically has a longer lifetime (or no expiry for classic PATs), increasing the window of exposure. Deploy keys follow the principle of least privilege: ArgoCD only needs to `git pull` — it should never need to push.

### Where does ArgoCD store repository credentials, and how are they protected?

ArgoCD stores repository credentials as **Kubernetes Secrets** in the `argocd` namespace, specifically:

- Secret name pattern: `repo-<hash>` or explicitly named via `argocd repo add`.
- The Secret contains the SSH private key (or HTTPS token) encoded in base64.
- These Secrets are labeled `argocd.argoproj.io/secret-type: repository`.

**Protection mechanisms:**
1. **Kubernetes RBAC:** Access to Secrets in the `argocd` namespace should be restricted. Only the ArgoCD repo-server service account and cluster administrators should have `get`/`list` access to Secrets in this namespace.
2. **etcd encryption:** Kubernetes Secrets are stored in etcd. Enabling encryption-at-rest for etcd (via `EncryptionConfiguration`) ensures the private key is not stored in plaintext on disk.
3. **Network isolation:** The `argocd` namespace should have NetworkPolicies restricting which pods can communicate with the Kubernetes API server to read these Secrets.
4. **Audit logging:** Kubernetes audit logs should be configured to record any access to Secrets in the `argocd` namespace, enabling detection of unauthorized credential access.

---

## B3. Sync Policy & Drift Detection

### Automated Sync with `selfHeal: true`

`selfHeal: true` means ArgoCD continuously monitors the live cluster state and compares it to the desired state in Git. If someone manually runs `kubectl apply`, `kubectl edit`, or `kubectl scale` to modify a resource that ArgoCD manages, ArgoCD will detect the divergence and **automatically revert the change** back to what Git declares.

**Why it matters:**
- **Prevents configuration drift.** Without self-healing, a developer who "quickly" patches a deployment via `kubectl` creates a state that exists only in the cluster — undocumented, unreviewed, and invisible to the team. The next ArgoCD sync might silently overwrite it (causing confusion) or, worse, ArgoCD might not sync at all if it believes the app is already in sync.
- **Enforces Git as the single source of truth.** If manual changes persist, Git is no longer authoritative. This undermines the entire GitOps model: you can no longer trust that `git log` reflects what is actually running in production.
- **Security control.** If an attacker gains limited `kubectl` access and modifies a deployment (e.g., changes the container image to a backdoored version, disables security contexts, or increases privileges), self-healing will revert the change within seconds. The attacker's modification is automatically rolled back without human intervention.

**Demonstration (proof: `proof/B3_selfheal.txt`):**

Git declares `replicaCount: 4`. A manual `kubectl scale` to 8 was reverted by ArgoCD within ~30 seconds:

```
BEFORE manual change:                         AFTER kubectl scale --replicas=8:
NAME         READY                            NAME         READY
recipe-api   4/4                              recipe-api   4/8   <- drift!

Wait 30s for ArgoCD self-heal:
NAME         READY
recipe-api   4/4   <- reverted to Git state, drift eliminated
```

### Pruning with `prune: true`

`prune: true` means that when a resource is **removed from Git** (e.g., a YAML file is deleted or a Helm template is removed), ArgoCD will **delete the corresponding resource from the cluster**.

**Security implication:** This is a double-edged sword:
- **Positive:** It prevents "ghost resources" — abandoned deployments, orphaned services, or forgotten Ingress rules that remain in the cluster after their code is removed. Ghost resources expand the attack surface because they continue running unmonitored and unpatched.
- **Risk:** If an attacker gains write access to the Git repository and removes a critical resource (e.g., a NetworkPolicy or a security-critical ConfigMap), ArgoCD will automatically delete it from the cluster. This is why repository access security (B2) is so critical — and why sensitive resources like Secrets should be excluded from automatic pruning.

### Resource Exclusions for Sensitive Resources

In our `argocd-cm.yaml`, we configured resource exclusions to prevent ArgoCD from automatically pruning Secrets:

```yaml
resource.exclusions: |
  - apiGroups:
      - ""
    kinds:
      - Secret
    clusters:
      - "*"
```

**Important caveat (learned during deployment):** A *global* exclusion of Secrets prevents ArgoCD from **creating** any Secret defined in a Helm chart (e.g., our chart's `templates/secret.yaml` that holds DB credentials). The result was pods stuck in `CreateContainerConfigError: secret "recipe-api-db-credentials" not found`.

The correct, more surgical approach is to use **per-Application `ignoreDifferences`** instead of a global exclusion. Our `applications/recipe-api.yaml` does this — it tells ArgoCD to ignore drift in a Secret's `/data` field (so manual edits to Secret values are not reverted) while still permitting creation. The global exclusion in `argocd-cm.yaml` was removed (see commit `8470a43`).

### What is "drift" in a GitOps context?

**Drift** is any discrepancy between the **desired state** (what is declared in Git) and the **live state** (what is actually running in the Kubernetes cluster). Drift can be caused by:

- Manual `kubectl` commands (most common)
- Other controllers or operators modifying resources
- Kubernetes mutating admission webhooks adding fields
- Failed or partial syncs leaving resources in an intermediate state

### Why is automated drift correction a security feature?

1. **Tamper resistance.** If an attacker modifies a running deployment (e.g., injects a sidecar container, changes environment variables, or disables security contexts), drift correction automatically reverts the change. The attacker would need to compromise the Git repository — a much harder target that leaves an audit trail — rather than just obtaining temporary `kubectl` access.

2. **Compliance enforcement.** Security policies encoded in Git (resource limits, security contexts, network policies) cannot be bypassed by manual overrides. Even well-intentioned "emergency" changes that weaken security are reverted, forcing the change through the proper Git-based review process.

3. **Incident detection.** Even if self-heal reverts a malicious change, the ArgoCD sync event is logged, including what drifted and when. This serves as an intrusion detection signal: unexpected drift in security-sensitive resources (security contexts, RBAC, network policies) should trigger alerts.

---

# Part C: GitOps Threat Model

## C1. Supply Chain Threats (3p)

### Trust Chain: Developer to Running Container

```
Developer  -->  Git Repo  -->  ArgoCD  -->  Helm Chart  -->  Container Registry  -->  Kubernetes
   (1)           (2)           (3)           (4)                  (5)                    (6)
```

### Threat Analysis at Each Link

#### (1) Developer

| Aspect | Detail |
|---|---|
| **What could be compromised?** | Developer's GitHub account (stolen credentials, session hijack, phishing), development machine (malware, keylogger), or Git signing key. |
| **What would the attacker gain?** | Ability to push arbitrary code changes — including malicious Helm chart modifications, backdoored container images, or weakened security configurations — that ArgoCD will automatically deploy to the cluster. |
| **Mitigations** | MFA on GitHub, branch protection rules requiring reviews, commit signing (GPG/SSH), mandatory PR approvals from a second developer, CODEOWNERS file for critical paths. |

#### (2) Git Repository

| Aspect | Detail |
|---|---|
| **What could be compromised?** | Repository access controls (a misconfigured collaborator, leaked deploy key, or compromised GitHub App), Git history manipulation (force-push), or GitHub itself (platform-level breach). |
| **What would the attacker gain?** | Full control over what ArgoCD deploys. Since Git is the single source of truth in GitOps, controlling the repo means controlling production. The attacker can modify Helm values, change container image references, weaken security policies, or delete resources (triggering pruning). |
| **Mitigations** | Branch protection (no force-push to main, required reviews, status checks), signed commits, read-only deploy keys for ArgoCD, audit logs, GitHub security alerts. |

#### (3) ArgoCD

| Aspect | Detail |
|---|---|
| **What could be compromised?** | ArgoCD admin credentials, ArgoCD API server (exposed without TLS/auth), the ArgoCD service account's Kubernetes RBAC permissions, or the repo-server component (which clones and renders Helm charts). |
| **What would the attacker gain?** | Ability to deploy arbitrary applications to the cluster, modify sync policies, add malicious repositories, disable self-healing, or access stored repository credentials (SSH keys, tokens). If the ArgoCD service account has cluster-admin privileges (which it does by default), the attacker effectively controls the entire cluster. |
| **Mitigations** | Strong admin password (changed from default), RBAC with least-privilege roles, network policies limiting ArgoCD API exposure, TLS for the API server, audit logging, restricting the ArgoCD service account's Kubernetes permissions via AppProjects. |

#### (4) Helm Chart

| Aspect | Detail |
|---|---|
| **What could be compromised?** | The Helm chart templates or values (via Git compromise), the Helm chart dependencies (a malicious subchart published to a public repository like Bitnami), or the chart rendering process (template injection). |
| **What would the attacker gain?** | If someone pushes a malicious Helm chart to the chart repository: ArgoCD will render the compromised templates and deploy them. The attacker could inject sidecar containers, modify the container image reference, add privileged security contexts, create ClusterRoleBindings granting them cluster-admin, or exfiltrate secrets via init containers. |
| **Detection** | Changes to Helm charts in Git would appear as commits — reviewable via PR. For third-party chart dependencies (like our `postgresql` subchart from Bitnami), we pin to a specific version (`15.5.38`) and include the chart archive in the `charts/` directory. Any change to the dependency would modify `Chart.lock`, which is a reviewable change. |
| **Controls from Exercise 2** | The CI pipeline from Exercise 2 generates an **SBOM** (Software Bill of Materials) for every built image, enabling detection of unexpected dependencies. **Image signing with Cosign** ensures that only images built by our CI pipeline can be verified as authentic. If an attacker swaps the image reference in a Helm chart to point to a malicious image, `cosign verify` would fail because the malicious image would not have a valid signature from our CI's OIDC identity. Integrating Cosign verification into an admission controller (like Kyverno or Connaisseur) would block unsigned images at the Kubernetes API level. |

#### (5) Container Registry

| Aspect | Detail |
|---|---|
| **What could be compromised?** | Registry credentials (GHCR token, Docker Hub PAT), the registry platform itself, or image tags (mutable tags like `latest` being overwritten). |
| **What would the attacker gain?** | Ability to push a malicious image under an existing tag. If the Helm chart references `image: ghcr.io/user/recipe-api:1.0.0` and the attacker can overwrite that tag, the next pod restart will pull the backdoored image. |
| **Mitigations** | Use image digests (`@sha256:...`) instead of mutable tags, Cosign image signatures, SBOM verification, registry access with least-privilege tokens, immutable tags (if the registry supports them), and admission controllers that enforce signature verification. |

#### (6) Kubernetes Cluster

| Aspect | Detail |
|---|---|
| **What could be compromised?** | Kubernetes API server (exposed publicly, weak auth), kubelet (node-level access), etcd (unencrypted secrets at rest), admission controllers (disabled or misconfigured), or the container runtime (breakout vulnerability). |
| **What would the attacker gain?** | Direct control over workloads, ability to exfiltrate secrets, pivot to other namespaces, or escape to the host node. |
| **Mitigations** | API server behind VPN/firewall, etcd encryption at rest, Pod Security Standards, network policies, RBAC with least-privilege, audit logging, runtime security monitoring (Falco), regular cluster updates. |

---

## C2. Access Control Analysis (1p)

### Identity Access Map

| Identity | Type | Access | Follows Least Privilege? |
|---|---|---|---|
| **ArgoCD service account** (`argocd-application-controller`) | Machine | Can create, modify, and delete any Kubernetes resource in namespaces managed by ArgoCD. By default has cluster-admin-level power. | Partially. Could be further restricted using ArgoCD AppProjects to limit which namespaces and resource types each Application can target. |
| **ArgoCD repo-server** | Machine | Read access to the Git repository (via SSH deploy key). Renders Helm charts. No direct Kubernetes API access beyond reading. | Yes. Read-only deploy key limits blast radius. |
| **CI/CD pipeline** (GitHub Actions) | Machine | `packages:write` to GHCR (push images), `id-token:write` (Cosign signing), `contents:read` (checkout code). Does NOT have `kubectl` or ArgoCD access. | Yes. Pipeline can only build and push images; it cannot deploy. Deployment is exclusively through Git + ArgoCD. |
| **Git repo collaborators** (developers) | Human | Can push to branches, create PRs. With branch protection, cannot push directly to `main` without review. Effectively control what gets deployed via Git. | Yes, if branch protection is enforced. No, if developers can push directly to `main` — then any developer can deploy anything. |
| **ArgoCD admin user** (`admin-user`) | Human | Full ArgoCD access: manage applications, repositories, clusters, accounts, RBAC policies. | Yes — this is the intended admin role, held by a small number of operators. |
| **ArgoCD developer user** (`dev-user`) | Human | Can view and sync ArgoCD applications. Cannot delete, create, or modify ArgoCD configuration. | Yes. Can observe and trigger deploys but cannot change the deployment pipeline itself. |
| **Kubernetes cluster admins** | Human | Full `cluster-admin` RBAC — can bypass ArgoCD entirely via `kubectl`. | Acceptable for break-glass scenarios, but in normal operations, all changes should go through Git. Direct `kubectl` changes will be reverted by ArgoCD's self-heal. |
| **Container registry** (GHCR) | Machine | Stores container images. ArgoCD's nodes pull images from here. Write access is limited to the CI pipeline. | Yes. Only CI can push; cluster nodes can only pull. |

---

## C3. Incident Response (2p)

### Scenario A: Unknown container image running in the cluster, not deployed through ArgoCD

**Detection:**
1. ArgoCD's drift detection should flag this: if the pod was created in a namespace ArgoCD manages, ArgoCD would show the Application as "OutOfSync" with unknown resources. If `prune: true` is enabled, ArgoCD would automatically delete the rogue pod.
2. If the pod is in a namespace ArgoCD does not manage, detection relies on runtime monitoring (e.g., Falco, a Kubernetes audit log pipeline, or periodic `kubectl get pods --all-namespaces` audits).
3. Check image signatures: `cosign verify <image>` — an unknown image will not have a valid signature from our CI pipeline.

**Immediate response (Contain):**
1. **Isolate the pod** — apply a NetworkPolicy that blocks all ingress/egress for the pod's labels, preventing it from communicating with other services or exfiltrating data.
2. **Capture forensic data** before deletion:
   - `kubectl logs <pod>` and `kubectl logs <pod> --previous` for container logs.
   - `kubectl describe pod <pod>` for the full pod spec (image, env vars, volumes, service account).
   - `kubectl get pod <pod> -o yaml > evidence.yaml` for the complete manifest.
   - Note the node the pod is running on for potential host-level investigation.
3. **Delete the pod** and any associated resources (Deployment, DaemonSet, Job, etc.): `kubectl delete pod <pod> --grace-period=0 --force`.

**Investigation:**
1. **Kubernetes audit logs** — search for who created the pod: what identity (user, service account), what source IP, what time.
2. **RBAC review** — identify how the creator had permissions to deploy outside ArgoCD. Tighten RBAC: in a GitOps model, no human should need `create pods` permission in application namespaces — only the ArgoCD service account should.
3. **Image analysis** — pull the unknown image and inspect it: `docker inspect`, `trivy image <image>`, check for malware, backdoors, or cryptocurrency miners.
4. **Check all nodes** — run `kubectl get pods --all-namespaces -o wide` to verify no other rogue pods exist.

**Remediation:**
1. Restrict Kubernetes RBAC so that only ArgoCD's service account can create/modify workloads in managed namespaces. Developers should interact through Git, not `kubectl`.
2. Implement an admission controller (OPA Gatekeeper, Kyverno) that rejects pods with unsigned images or images not from the approved registry.
3. Enable and monitor Kubernetes audit logging for `create`/`update` operations on workload resources.

---

### Scenario B: Developer's GitHub account compromised; attacker pushes malicious Helm chart change

**Detection:**
1. **Branch protection alerts** — if the attacker pushed directly to `main` (bypassing branch protection), GitHub sends an alert. If they created a PR, the review process should catch suspicious changes.
2. **ArgoCD sync notification** — ArgoCD will detect the new commit and begin syncing. If Slack/webhook notifications are configured, the team sees an unexpected sync event.
3. **CI pipeline artifacts** — the CI pipeline from Exercise 2 will run on the push. If the attacker changed the container image to one that is not in our registry, Trivy will scan it and potentially flag vulnerabilities. Cosign verification (if integrated into the admission controller) will reject unsigned images.
4. **Git commit history** — the malicious commit will have the compromised developer's identity but may show unusual patterns: unusual commit time, unfamiliar IP in GitHub audit logs, changes to security-sensitive files.

**Immediate response (Contain):**
1. **Disable the compromised GitHub account** — remove the developer from the repository or organization immediately to prevent further pushes.
2. **Revert the malicious commit** — `git revert <malicious-commit>` and push to `main`. ArgoCD will auto-sync the revert, rolling back the malicious change.
3. **If already deployed** — check running pods: `kubectl get pods -n recipe-api -o yaml | grep image:`. If the malicious image is running, manually trigger an ArgoCD sync to force the revert: `argocd app sync recipe-api --force`.
4. **Rotate all secrets** that the attacker may have had access to via the Git repo (deploy keys, any committed secrets in Git history).

**Investigation:**
1. **GitHub audit log** — check the compromised account's activity: what commits, PRs, settings changes, or collaborator additions were made.
2. **Git diff analysis** — `git diff <last-known-good>..<malicious-commit>` to understand exactly what was changed. Look for: changed container images, added init containers, modified security contexts, new environment variables, weakened network policies.
3. **Check for persistence** — did the attacker add a new SSH key or PAT to the compromised account? Did they add themselves as a collaborator? Did they create a GitHub App with repository access?
4. **Container forensics** — if a malicious image was deployed and ran, capture logs and network traffic to determine if data was exfiltrated.

**Remediation:**
1. **Enforce commit signing** — require signed commits on the `main` branch. GPG/SSH-signed commits prove the author's identity; unsigned commits from a stolen session cookie would be rejected.
2. **Require 2+ PR reviewers** for changes to security-sensitive paths (`**/templates/**`, `**/values*.yaml`, `argocd/**`, `applications/**`) via CODEOWNERS.
3. **Enable GitHub's "Require linear history"** — prevents force-pushes that could hide malicious commits.
4. **Implement image signature verification** in a Kubernetes admission controller (Kyverno + Cosign policy) — even if a malicious Helm chart references an attacker's image, the cluster will refuse to run it because it lacks a valid Cosign signature from our CI pipeline.
5. **Review and rotate** the compromised developer's credentials: GitHub password, SSH keys, GPG keys, API tokens, and any secrets they had access to across all systems.
