# Secure Cluster Design
> **Target Audience:** Senior Engineers (8+ years) preparing for DevSecOps / Platform Security interviews  
> **Companion files:** `Kubernetes-Security-Foundations.md`, `15-Kubernetes-Design-Patterns.md`

---

## Table of Contents
1. [Multi-tenancy Models](#1-multi-tenancy-models)
2. [CIS Kubernetes Benchmark](#2-cis-kubernetes-benchmark)
3. [Control Plane Hardening](#3-control-plane-hardening)
4. [Worker Node Hardening](#4-worker-node-hardening)
5. [etcd Security](#5-etcd-security)
6. [Network Segmentation](#6-network-segmentation)
7. [Audit Policies](#7-audit-policies)
8. [Node Authorization](#8-node-authorization)
9. [Secure Cluster Architecture Diagram](#9-secure-cluster-architecture-diagram)
10. [Tooling: kube-bench and Cluster Audit](#10-tooling-kube-bench-and-cluster-audit)
11. [Interview Q&A — 12 Senior-Level Questions](#11-interview-qa--12-senior-level-questions)
12. [References](#12-references)

---

## 1. Multi-tenancy Models

Multi-tenancy in Kubernetes is a spectrum — there is no single correct answer. The choice depends on the trust model between tenants, compliance requirements, and operational cost tolerance.

### 1.1 Soft Tenancy (Namespace-based)

**Definition:** Multiple tenants share the same control plane, worker nodes, and network fabric. Separation is enforced by Kubernetes primitives: RBAC, NetworkPolicy, Resource Quotas, Pod Security Admission.

```
┌─────────────────────── Single Cluster ─────────────────────────┐
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │  namespace:     │  │  namespace:     │  │  namespace:     │ │
│  │  team-alpha     │  │  team-beta      │  │  team-gamma     │ │
│  │  RBAC: alpha-*  │  │  RBAC: beta-*   │  │  RBAC: gamma-*  │ │
│  │  NetworkPolicy  │  │  NetworkPolicy  │  │  NetworkPolicy  │ │
│  │  ResourceQuota  │  │  ResourceQuota  │  │  ResourceQuota  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
│  ─── Shared: kube-apiserver, etcd, kubelet, kernel ──────────── │
└────────────────────────────────────────────────────────────────┘
```

**Pros:** Low operational overhead, cost-efficient, unified observability  
**Cons:** Shared kernel (container escape → node compromise), covert channels possible, noisy-neighbor CPU/memory unless PriorityClasses configured, blast radius of control plane vulnerability affects all tenants

**Threat Model:** Soft tenancy is appropriate when tenants are **within the same trust boundary** (e.g., different dev teams in one company). Not appropriate for hosting untrusted third-party code.

### 1.2 Hard Tenancy (Cluster-per-tenant / Virtual Cluster)

**Option A: Dedicated clusters per tenant**
- Full isolation of control plane and nodes
- Operationally expensive (N clusters × management overhead)
- Required for: regulated workloads (PCI-DSS, HIPAA), untrusted tenant code, different compliance postures

**Option B: Virtual Clusters (vCluster)**
- Each tenant gets their own kube-apiserver running inside a namespace of the host cluster
- Tenant control plane is isolated; tenant cannot see host cluster objects
- Nodes are still shared (improved over soft tenancy, but still shared kernel)
- Tooling: `vcluster` (Loft Labs), `kcp` (Red Hat)

**Option C: Hypervisor-based isolation (Kata Containers / gVisor)**
- Each pod runs in a lightweight VM or with a sandboxed kernel
- Provides kernel-level isolation without full VM overhead
- Use with untrusted workloads (e.g., running user-submitted code)

### 1.3 Tenancy Decision Matrix

| Requirement | Soft (NS) | vCluster | Dedicated Cluster |
|---|---|---|---|
| Different dev teams, same company | ✅ | ✅ | Overkill |
| Different business units with shared platform | ✅ with controls | ✅ | Optional |
| External customers (SaaS) | ❌ | ✅ | ✅ |
| Regulated workloads (PCI, HIPAA) | Risk assessment required | ✅ | ✅ recommended |
| Untrusted code execution | ❌ | ❌ without Kata | ✅ + Kata |
| Different Kubernetes versions | ❌ | ✅ | ✅ |
| Cost optimization (10+ tenants) | ✅ | ✅ | ❌ |

---

## 2. CIS Kubernetes Benchmark

The CIS (Center for Internet Security) Kubernetes Benchmark is the industry-standard hardening guide. It is organized into:
- **Level 1:** Practical hardening with low operational impact
- **Level 2:** Defense-in-depth; may have higher operational impact

### 2.1 Key Sections

| Section | Description |
|---|---|
| 1.x | Control Plane Configuration (API server, scheduler, controller manager) |
| 2.x | etcd Configuration |
| 3.x | Control Plane Node Configuration Files (permissions, ownership) |
| 4.x | Worker Node Configuration (kubelet) |
| 5.x | Kubernetes Policies (RBAC, PSA, Network Policies, Secrets management) |

### 2.2 High-Priority CIS Controls

```
CIS 1.2.1  - Ensure --anonymous-auth=false on API server
CIS 1.2.6  - Ensure --kubelet-certificate-authority is set
CIS 1.2.7  - Ensure --authorization-mode includes Node,RBAC
CIS 1.2.10 - Ensure --enable-admission-plugins includes PodSecurity (or equivalent)
CIS 1.2.16 - Ensure --audit-log-path is set
CIS 1.2.24 - Ensure --service-account-lookup=true
CIS 1.2.32 - Ensure --encryption-provider-config is set (Secrets encryption)
CIS 2.1    - Ensure --cert-file and --key-file are set for etcd
CIS 2.2    - Ensure --client-cert-auth=true for etcd
CIS 4.2.1  - Ensure --anonymous-auth=false on kubelet
CIS 4.2.2  - Ensure --authorization-mode=Webhook on kubelet
CIS 5.1.1  - Ensure cluster-admin role is used only where required
CIS 5.2.x  - Pod Security Admission (privileged/baseline/restricted)
CIS 5.4.1  - Prefer using Secrets as files over env variables
CIS 5.7.2  - Ensure Seccomp profile is set to docker/default or runtime/default
```

### 2.3 Scoring and Automated Assessment

Use `kube-bench` to automatically assess CIS compliance (see Section 10).

---

## 3. Control Plane Hardening

### 3.1 API Server Hardening

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml (static pod)
spec:
  containers:
    - command:
        - kube-apiserver
        # Authentication hardening
        - --anonymous-auth=false
        - --oidc-issuer-url=https://sso.company.com
        - --oidc-client-id=kubernetes
        - --oidc-username-claim=email
        - --oidc-groups-claim=groups
        # Authorization
        - --authorization-mode=Node,RBAC
        # Admission control
        - --enable-admission-plugins=NodeRestriction,PodSecurity,ResourceQuota,LimitRanger,ServiceAccount,DefaultStorageClass,DefaultTolerationSeconds,MutatingAdmissionWebhook,ValidatingAdmissionWebhook
        - --disable-admission-plugins=AlwaysAdmit,AlwaysPullImages  # AlwaysPullImages has side effects
        # TLS
        - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
        - --tls-private-key-file=/etc/kubernetes/pki/apiserver.key
        - --client-ca-file=/etc/kubernetes/pki/ca.crt
        - --kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt
        - --kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key
        - --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - --tls-min-version=VersionTLS12
        # Secrets encryption
        - --encryption-provider-config=/etc/kubernetes/enc/config.yaml
        # Audit
        - --audit-log-path=/var/log/kubernetes/audit.log
        - --audit-policy-file=/etc/kubernetes/audit/policy.yaml
        - --audit-log-maxage=30
        - --audit-log-maxbackup=10
        - --audit-log-maxsize=100
        # Service account
        - --service-account-lookup=true
        - --service-account-key-file=/etc/kubernetes/pki/sa.pub
        - --service-account-signing-key-file=/etc/kubernetes/pki/sa.key
        - --service-account-issuer=https://kubernetes.default.svc
        # Misc security
        - --profiling=false
        - --request-timeout=60s
        - --kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt
```

### 3.2 Controller Manager Hardening

```yaml
spec:
  containers:
    - command:
        - kube-controller-manager
        - --use-service-account-credentials=true   # Each controller gets its own SA
        - --service-account-private-key-file=/etc/kubernetes/pki/sa.key
        - --root-ca-file=/etc/kubernetes/pki/ca.crt
        - --profiling=false
        - --terminated-pod-gc-threshold=10          # Limit completed pod accumulation
        - --feature-gates=RotateKubeletServerCertificate=true
        - --tls-cert-file=/etc/kubernetes/pki/controller-manager.crt
        - --tls-private-key-file=/etc/kubernetes/pki/controller-manager.key
        - --kubeconfig=/etc/kubernetes/controller-manager.conf
        - --authentication-kubeconfig=/etc/kubernetes/controller-manager.conf
        - --authorization-kubeconfig=/etc/kubernetes/controller-manager.conf
```

### 3.3 Scheduler Hardening

```yaml
spec:
  containers:
    - command:
        - kube-scheduler
        - --profiling=false
        - --kubeconfig=/etc/kubernetes/scheduler.conf
        - --authentication-kubeconfig=/etc/kubernetes/scheduler.conf
        - --authorization-kubeconfig=/etc/kubernetes/scheduler.conf
        - --tls-cert-file=/etc/kubernetes/pki/scheduler.crt
        - --tls-private-key-file=/etc/kubernetes/pki/scheduler.key
```

### 3.4 File Permissions (CIS Section 1.1)

```bash
# API server pod spec
chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml
chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml

# PKI files
chmod 600 /etc/kubernetes/pki/*.key
chmod 644 /etc/kubernetes/pki/*.crt
chown root:root /etc/kubernetes/pki/

# Admin kubeconfig
chmod 600 /etc/kubernetes/admin.conf
chown root:root /etc/kubernetes/admin.conf
```

---

## 4. Worker Node Hardening

### 4.1 kubelet Configuration

```yaml
# /var/lib/kubelet/config.yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration

# Authentication
authentication:
  anonymous:
    enabled: false                     # CIS 4.2.1
  webhook:
    enabled: true                      # Delegate to API server
    cacheTTL: 2m
  x509:
    clientCAFile: /etc/kubernetes/pki/ca.crt

# Authorization
authorization:
  mode: Webhook                        # CIS 4.2.2

# TLS
tlsCertFile: /var/lib/kubelet/pki/kubelet.crt
tlsPrivateKeyFile: /var/lib/kubelet/pki/kubelet.key
tlsMinVersion: VersionTLS12
tlsCipherSuites:
  - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

# Certificate rotation
rotateCertificates: true               # Rotate client cert
serverTLSBootstrap: true               # Bootstrap and rotate server cert

# Pod security
protectKernelDefaults: true            # CIS 4.2.6
readOnlyPort: 0                        # Disable read-only port (CIS 4.2.4)

# Event limits
eventRecordQPS: 5

# Security defaults
seccompDefault: true                   # Enable RuntimeDefault seccomp for all pods

# Streaming connection idle timeout
streamingConnectionIdleTimeout: 5m

# Eviction
evictionHard:
  memory.available: "100Mi"
  nodefs.available: "10%"
  imagefs.available: "15%"

# Reserve resources for system
systemReserved:
  cpu: "500m"
  memory: "500Mi"
kubeReserved:
  cpu: "500m"
  memory: "500Mi"
```

### 4.2 Node-level OS Hardening

```bash
# Disable unused kernel modules
cat <<EOF >> /etc/modprobe.d/kubernetes-blacklist.conf
# Uncommon network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

# Kernel parameters
cat <<EOF >> /etc/sysctl.d/99-kubernetes-hardening.conf
# Disable IP forwarding for host network (containers need it — configure CNI separately)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
# Protect kernel pointers
kernel.kptr_restrict = 2
# Restrict dmesg (avoid container information leakage)
kernel.dmesg_restrict = 1
# Core dumps
kernel.core_pattern = |/bin/false
EOF
sysctl --system

# Ensure auditd is running (node-level audit separate from K8s audit)
systemctl enable auditd --now

# Set kubelet file permissions
chmod 600 /var/lib/kubelet/config.yaml
chown root:root /var/lib/kubelet/config.yaml

# Ensure container runtime socket is protected
chmod 660 /run/containerd/containerd.sock
chown root:containerd /run/containerd/containerd.sock
```

### 4.3 Container Runtime (containerd) Hardening

```toml
# /etc/containerd/config.toml
version = 2

[plugins."io.containerd.grpc.v1.cri"]
  # Disable privileged containers globally (if your workloads allow)
  # disable_privileged_containers = true  # Note: Kubernetes 1.28+ feature

  [plugins."io.containerd.grpc.v1.cri".containerd]
    default_runtime_name = "runc"

    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
      runtime_type = "io.containerd.runc.v2"
      [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
        SystemdCgroup = true
        # Kata Containers runtime for untrusted workloads:
    [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.kata]
      runtime_type = "io.containerd.kata.v2"

  [plugins."io.containerd.grpc.v1.cri".registry]
    [plugins."io.containerd.grpc.v1.cri".registry.mirrors]
      [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
        endpoint = ["https://registry-mirror.company.com"]
```

### 4.4 Node Labeling and Taints for Isolation

```bash
# Taint nodes for sensitive workloads (PCI scope)
kubectl taint nodes node-pci-1 compliance=pci:NoSchedule

# Label nodes for affinity rules
kubectl label nodes node-pci-1 compliance=pci

# Workload targeting PCI nodes
spec:
  tolerations:
    - key: compliance
      operator: Equal
      value: pci
      effect: NoSchedule
  nodeSelector:
    compliance: pci
```

---

## 5. etcd Security

### 5.1 Network Isolation

```bash
# etcd should ONLY be accessible from API server IPs
# Example iptables rule (production: use firewalld or cloud security groups)
iptables -A INPUT -p tcp --dport 2379 -s <api-server-ip>/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 2379 -j DROP
iptables -A INPUT -p tcp --dport 2380 -s <etcd-peer-ip-1>/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 2380 -s <etcd-peer-ip-2>/32 -j ACCEPT
iptables -A INPUT -p tcp --dport 2380 -j DROP
```

### 5.2 etcd Hardening Flags

```yaml
# /etc/kubernetes/manifests/etcd.yaml
spec:
  containers:
    - command:
        - etcd
        # Peer TLS (etcd-to-etcd communication)
        - --peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt
        - --peer-key-file=/etc/kubernetes/pki/etcd/peer.key
        - --peer-client-cert-auth=true             # CIS 2.4
        - --peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
        # Client TLS (API server-to-etcd communication)
        - --cert-file=/etc/kubernetes/pki/etcd/server.crt
        - --key-file=/etc/kubernetes/pki/etcd/server.key
        - --client-cert-auth=true                  # CIS 2.2
        - --trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt
        # Bind only to internal IP
        - --listen-client-urls=https://127.0.0.1:2379,https://<node-ip>:2379
        - --listen-peer-urls=https://<node-ip>:2380
        # Metrics endpoint — restrict to internal only
        - --listen-metrics-urls=http://127.0.0.1:2381
        # Auto-compaction to limit resource consumption
        - --auto-compaction-retention=8            # hours
        # Quota
        - --quota-backend-bytes=8589934592         # 8GB
```

### 5.3 etcd Backup and Recovery

```bash
# Backup etcd (run on etcd node)
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd-$(date +%Y%m%d-%H%M%S).db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Verify backup integrity
ETCDCTL_API=3 etcdctl snapshot status /backup/etcd-*.db --write-out=table

# Encrypt the backup (backup contains all secrets!)
gpg --symmetric --cipher-algo AES256 /backup/etcd-*.db

# Restore (emergency procedure)
ETCDCTL_API=3 etcdctl snapshot restore /backup/etcd-backup.db \
  --data-dir=/var/lib/etcd-restore \
  --initial-cluster=<cluster-config> \
  --initial-cluster-token=<token> \
  --initial-advertise-peer-urls=https://<ip>:2380
```

> **Senior Insight:** etcd backups must be treated with the same security as live etcd. A backup contains all Secrets in plaintext (pre-encryption) or KMS-wrapped DEKs. Store backups in encrypted storage (S3 SSE-KMS) with strict access controls and test restoration regularly.

---

## 6. Network Segmentation

### 6.1 Defense-in-Depth Network Model

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 1: Cloud/Infrastructure Firewall / Security Groups    │
│  - Only port 443 (ingress) and 6443 (API) exposed            │
│  - etcd ports 2379/2380 internal only                        │
│  - Node-to-node on defined ports only                        │
├──────────────────────────────────────────────────────────────┤
│  Layer 2: CNI NetworkPolicy (Kubernetes L3/L4)               │
│  - Default deny all ingress + egress per namespace           │
│  - Explicit allow: app → database, app → cache               │
│  - DNS always allowed (kube-dns UDP/TCP 53)                  │
├──────────────────────────────────────────────────────────────┤
│  Layer 3: Service Mesh mTLS (Istio / Cilium)                 │
│  - L7 policy (HTTP methods, paths, headers)                  │
│  - Automatic mTLS between all services                       │
│  - SPIFFE/SPIRE identity per workload                        │
├──────────────────────────────────────────────────────────────┤
│  Layer 4: Ingress Controller + WAF                           │
│  - TLS termination                                           │
│  - Rate limiting, DDoS protection                            │
│  - WAF rules (OWASP Top 10)                                  │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 NetworkPolicy Templates

```yaml
# 1. Default deny all — apply to every namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress
---
# 2. Allow DNS egress (required for pod name resolution)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: prod
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
---
# 3. Application-level policy (payment service → postgres only)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: payment-to-postgres
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: payment-service
      ports:
        - protocol: TCP
          port: 5432
---
# 4. Allow ingress controller → application
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-to-app
  namespace: prod
spec:
  podSelector:
    matchLabels:
      app: payment-service
  policyTypes:
    - Ingress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
```

### 6.3 Cilium L7 Network Policy (Service Mesh-lite)

```yaml
# Cilium CiliumNetworkPolicy: restrict HTTP methods and paths
apiVersion: "cilium.io/v2"
kind: CiliumNetworkPolicy
metadata:
  name: api-gateway-policy
  namespace: prod
spec:
  endpointSelector:
    matchLabels:
      app: payment-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: api-gateway
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: "POST"
                path: "/api/v1/payment"
              - method: "GET"
                path: "/healthz"
```

---

## 7. Audit Policies

### 7.1 Tiered Audit Policy for Production

The goal is maximum security signal with minimum operational noise:

```yaml
# /etc/kubernetes/audit/policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived

rules:
  # ── TIER 1: Critical security events — full request+response ──────────────
  # Pod exec/attach — interactive container access
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # RBAC mutations — privilege changes
  - level: RequestResponse
    verbs: ["create", "update", "patch", "delete"]
    resources:
      - group: "rbac.authorization.k8s.io"
        resources:
          - clusterroles
          - clusterrolebindings
          - roles
          - rolebindings

  # SA token creation — potential impersonation
  - level: RequestResponse
    verbs: ["create"]
    resources:
      - group: ""
        resources: ["serviceaccounts/token"]

  # ── TIER 2: Sensitive data access — metadata only (no secret values) ──────
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]

  # ── TIER 3: Workload mutations — request body (no response) ──────────────
  - level: Request
    verbs: ["create", "update", "patch", "delete", "deletecollection"]
    resources:
      - group: "apps"
        resources:
          - deployments
          - replicasets
          - daemonsets
          - statefulsets
      - group: "batch"
        resources: ["jobs", "cronjobs"]

  # ── TIER 4: Namespace lifecycle ───────────────────────────────────────────
  - level: RequestResponse
    verbs: ["create", "delete", "update"]
    resources:
      - group: ""
        resources: ["namespaces"]

  # ── SUPPRESS: High-volume low-value events ────────────────────────────────
  # kube-proxy endpoint watch
  - level: None
    users: ["system:kube-proxy"]
    verbs: ["watch"]
    resources:
      - group: ""
        resources: ["endpoints", "services", "nodes"]

  # Node self-reporting
  - level: None
    users: ["system:node:*"]
    verbs: ["get", "list", "watch"]
    resources:
      - group: ""
        resources: ["nodes", "pods"]

  # Health checks from load balancers / liveness probes
  - level: None
    nonResourceURLs: ["/healthz*", "/readyz*", "/livez*", "/metrics"]

  # ── DEFAULT: Metadata for everything else ────────────────────────────────
  - level: Metadata
    omitStages:
      - RequestReceived
```

### 7.2 Shipping Audit Logs to SIEM

```yaml
# Webhook backend config (/etc/kubernetes/audit/webhook.yaml)
apiVersion: v1
kind: Config
clusters:
  - name: falco-webhook
    cluster:
      server: https://falco-audit-receiver.monitoring.svc.cluster.local:9765/k8s-audit
      certificate-authority: /etc/kubernetes/pki/ca.crt
users:
  - name: api-server-user
    user:
      client-certificate: /etc/kubernetes/pki/audit-webhook.crt
      client-key: /etc/kubernetes/pki/audit-webhook.key
contexts:
  - name: webhook
    context:
      cluster: falco-webhook
      user: api-server-user
current-context: webhook
```

```bash
# API server flags to enable webhook backend
--audit-webhook-config-file=/etc/kubernetes/audit/webhook.yaml
--audit-webhook-initial-backoff=2s
--audit-webhook-batch-max-size=400
--audit-webhook-batch-max-wait=3s
--audit-webhook-throttle-qps=10
```

---

## 8. Node Authorization

### 8.1 Node Authorizer + NodeRestriction

The **Node authorizer** is a special-purpose authorizer for `system:node:*` users (kubelets). It enforces:

1. A kubelet can only `get`/`watch`/`list` pods **scheduled to its node**
2. A kubelet can only read secrets/configmaps for pods **on its node**
3. A kubelet can only update the status of its **own node**

Without NodeRestriction, a compromised node could read any secret in the cluster or modify node labels to appear as a control-plane node.

```
Authorization chain: Node → RBAC

system:node:worker-1 → Node authorizer: allowed to read secrets for pods on worker-1
system:node:worker-1 → RBAC: no ClusterRole needed for node operations
```

### 8.2 Enabling Node Authorization

```bash
# Required API server flags (both must be set together)
--authorization-mode=Node,RBAC

# Required admission plugin (prevents label spoofing)
--enable-admission-plugins=NodeRestriction,...
```

### 8.3 Bootstrap Flow for New Nodes

```
1. New node starts with bootstrap token
2. Kubelet uses token to request a client certificate (CSR)
3. kube-controller-manager approves CSR (if --approve-all-kubelet-csrs is set,
   or manually via: kubectl certificate approve <csr-name>)
4. kubelet stores the signed certificate
5. Future API calls use the certificate (CN=system:node:<hostname>, O=system:nodes)
6. Node authorizer validates the certificate's CN/O
```

```bash
# Monitor pending CSRs
kubectl get csr

# Approve a specific CSR
kubectl certificate approve node-csr-<hash>

# For production: use cert-manager or cluster-specific CSR approver
# Never use --approve-all-kubelet-csrs=true in production (allows any node to join)
```

### 8.4 Node Isolation via Taints and Admission

```yaml
# Dedicate nodes to specific workloads
# Taint: only pods with matching toleration are scheduled here
kubectl taint nodes <node-name> dedicated=frontend:NoSchedule

# Pod toleration
spec:
  tolerations:
    - key: dedicated
      operator: Equal
      value: frontend
      effect: NoSchedule
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: dedicated
                operator: In
                values: [frontend]
```

---

## 9. Secure Cluster Architecture Diagram

```mermaid
graph TB
    subgraph "Internet / External"
        Users["👥 Users / Developers\n(OIDC / MFA)"]
        LB["🌐 Load Balancer\nTLS 443"]
        AdminVPN["🔒 Admin VPN\nBreak-glass access only"]
    end

    subgraph "DMZ / Perimeter"
        WAF["🛡️ WAF + DDoS\nCloud Armor / Cloudflare"]
        IngressCtrl["📥 Ingress Controller\nnginx / Envoy\nTLS Termination"]
    end

    subgraph "Control Plane (Private Subnet)"
        direction TB
        APIServer["🔒 kube-apiserver\n:6443 (mTLS)\nOIDC AuthN\nNode+RBAC AuthZ\nAdmission Webhooks"]
        etcd["🗄️ etcd Cluster (3-node HA)\nmTLS peer communication\nKMS encryption at rest\n:2379 (API server only)"]
        KMS["🔐 Cloud KMS\nEnvelope Encryption\nAudit Trail"]
        AuditLog["📋 Audit Log\n→ SIEM (Splunk/Elastic)\n→ Falco Alerting"]
        Scheduler["📅 Scheduler\nmTLS"]
        CtrlMgr["⚙️ Controller Mgr\nPer-SA credentials"]
        OPA["⚖️ OPA/Gatekeeper\nPolicy Engine\nAdmission Webhook"]
    end

    subgraph "Data Plane — Prod Nodes (Private Subnet)"
        direction TB
        Node1["🖥️ Node 1\nkubelet (Webhook AuthZ)\ncontainerd\nSeccomp/AppArmor"]
        Node2["🖥️ Node 2\nkubelet (Webhook AuthZ)\ncontainerd\nSeccomp/AppArmor"]
        Node3["🖥️ Node 3\nkubelet (Webhook AuthZ)\ncontainerd\nSeccomp/AppArmor"]
    end

    subgraph "Data Plane — System Nodes (Private Subnet)"
        direction TB
        SysNode["🖥️ System Node\nFalco DaemonSet\nPrometheus Node Exporter\nFluentd/Vector (log shipping)"]
    end

    subgraph "Network Layer"
        CNI["🕸️ Cilium / Calico\nNetworkPolicy Enforcement\neBPF L7 Observability\nWireGuard Encryption (optional)"]
    end

    subgraph "Storage"
        StorageClass["💾 Encrypted PVs\nStorage Class: encrypted\nCloud Provider KMS backed"]
    end

    subgraph "Registry"
        Registry["📦 Private Registry\nImage Signing (Cosign)\nVulnerability Scanning\nImmutable Tags"]
    end

    Users -->|"HTTPS"| LB
    LB --> WAF
    WAF --> IngressCtrl
    IngressCtrl -->|"Internal HTTP"| Node1
    IngressCtrl -->|"Internal HTTP"| Node2

    AdminVPN -->|"mTLS (X.509)"| APIServer

    APIServer <-->|"mTLS"| etcd
    etcd <-->|"Envelope Encryption"| KMS
    APIServer --> AuditLog
    APIServer <-->|"Admission Webhook"| OPA
    APIServer <-->|"mTLS"| Scheduler
    APIServer <-->|"mTLS"| CtrlMgr
    APIServer <-->|"mTLS (Webhook AuthZ)"| Node1
    APIServer <-->|"mTLS (Webhook AuthZ)"| Node2
    APIServer <-->|"mTLS (Webhook AuthZ)"| Node3

    Node1 <-->|"NetworkPolicy"| CNI
    Node2 <-->|"NetworkPolicy"| CNI
    Node3 <-->|"NetworkPolicy"| CNI

    Node1 --> StorageClass
    Node2 --> StorageClass
    Node3 --> Registry

    SysNode -->|"DaemonSet monitoring"| Node1
    SysNode -->|"DaemonSet monitoring"| Node2
    SysNode -->|"DaemonSet monitoring"| Node3
```

---

## 10. Tooling: kube-bench and Cluster Audit

### 10.1 kube-bench — CIS Benchmark Automated Assessment

```bash
# Run kube-bench as a Kubernetes Job
kubectl apply -f https://raw.githubusercontent.com/aquasecurity/kube-bench/main/job.yaml

# Check results
kubectl logs job/kube-bench

# Run locally on control plane node (most accurate)
kube-bench run --targets master

# Run on worker node
kube-bench run --targets node

# Generate JSON report for SIEM ingestion
kube-bench run --targets master --json > kube-bench-results.json

# Run specific checks (by CIS ID)
kube-bench run --check 1.2.1,1.2.6,4.2.1

# Generate HTML report
kube-bench run --targets master --html > kube-bench-report.html
```

**Understanding kube-bench output:**
```
[PASS] 1.2.1 Ensure that the --anonymous-auth argument is set to false
[FAIL] 1.2.6 Ensure that the --kubelet-certificate-authority argument is set
[WARN] 1.2.10 Ensure that the admission control plugin PodSecurity is set
[INFO] 1.2.16 Ensure that the --audit-log-path argument is set

== Summary ==
33 checks PASS
5 checks FAIL
10 checks WARN
```

### 10.2 kube-audit / RBAC Audit Scripts

```bash
# Find all subjects with cluster-admin binding
kubectl get clusterrolebindings \
  -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.metadata.name}{"\t"}{.subjects[*].name}{"\n"}{end}'

# Find all service accounts with wildcard permissions
kubectl get clusterroles -o json | \
  jq -r '.items[] | select(.rules[].verbs[] == "*") | .metadata.name'

# Find all bindings to cluster-admin that are NOT system:masters or system:admin
kubectl get clusterrolebindings -o json | \
  jq -r '.items[] | select(.roleRef.name == "cluster-admin") | 
  .metadata.name + " -> " + (.subjects // [] | map(.name) | join(", "))'

# Enumerate what a specific SA can do
kubectl auth can-i --list \
  --as=system:serviceaccount:prod:payment-service \
  -n prod

# Find all service accounts that can read secrets cluster-wide
kubectl get clusterroles -o json | jq -r '
  .items[] | 
  select(.rules[]? | 
    (.resources[]? == "secrets" or .resources[]? == "*") and 
    (.verbs[]? == "get" or .verbs[]? == "list" or .verbs[]? == "*")
  ) | .metadata.name'

# Check etcd encryption status
kubectl get secret test-enc -n default -o jsonpath='{.data.key}' | base64 -d
# If readable as plaintext → encryption not working

# Run kube-score for manifest quality
kube-score score deployment.yaml

# Run Polaris for cluster-wide policy scan
polaris audit --config polaris-config.yaml --format json > polaris-report.json

# Run Trivy for cluster-wide vulnerability/misconfiguration scan
trivy k8s --report summary cluster
trivy k8s --severity HIGH,CRITICAL cluster

# Run Falco for runtime threat detection rules test
falco -r /etc/falco/falco_rules.yaml --dry-run
```

### 10.3 Continuous Compliance with CI/CD

```bash
# Integrate kube-bench into CI pipeline (post-deploy gate)
#!/bin/bash
set -euo pipefail

echo "Running CIS Kubernetes Benchmark..."
RESULTS=$(kubectl exec -n kube-system ds/kube-bench -- kube-bench run --json 2>/dev/null)

FAIL_COUNT=$(echo "$RESULTS" | jq '[.[] | .tests[] | .results[] | select(.status=="FAIL")] | length')
CRITICAL_FAILS=$(echo "$RESULTS" | jq -r '[.[] | .tests[] | .results[] | select(.status=="FAIL" and (.test_number | startswith("1.2") or startswith("2.") or startswith("4.2")))] | .[].test_number')

echo "Total failures: $FAIL_COUNT"
echo "Critical failures: $CRITICAL_FAILS"

if [ "$FAIL_COUNT" -gt 10 ]; then
  echo "❌ CIS Benchmark: Too many failures ($FAIL_COUNT). Blocking deployment."
  exit 1
fi
echo "✅ CIS Benchmark passed within acceptable threshold"
```

---

## 11. Interview Q&A — 12 Senior-Level Questions

---

### Q1: What is the difference between soft and hard multi-tenancy in Kubernetes, and how do you advise a customer choosing between them?

**Model Answer:**

**Soft tenancy** uses namespace isolation with RBAC, NetworkPolicy, Resource Quotas, and Pod Security Admission. All tenants share the kernel, container runtime, and control plane. It is appropriate when tenants are **internal and mutually trusted** — different teams within the same organization. The threat model assumes no hostile code execution and that namespace escapes are out of scope.

**Hard tenancy** provides kernel-level isolation via dedicated clusters, virtual clusters (vCluster), or hypervisor-based isolation (Kata Containers). Required when:
- Tenants are external customers (SaaS model)
- Tenants have different compliance postures (PCI tenant must be isolated from non-PCI)
- Tenant workloads execute untrusted code (FaaS, user-uploaded containers)

**Advisory framework:**
1. What is the trust relationship between tenants? (internal team vs external customer)
2. What is the blast radius of a container escape? (acceptable vs unacceptable)
3. What are the compliance requirements? (PCI requires network segmentation)
4. What is the operational budget? (hard tenancy multiplies platform complexity)

For most enterprise customers, a hybrid model works: soft tenancy for dev/staging with hard isolation (dedicated cluster or vCluster) for production tenants.

**What the interviewer is looking for:** Structured thinking about trust models, not just listing features; connects technical choice to business risk.

---

### Q2: Walk me through how you would harden a new EKS cluster for a PCI-DSS workload.

**Model Answer:**

PCI-DSS requires network segmentation, access control, encryption, and audit logging. Mapping to EKS:

**1. Network Segmentation:**
- VPC with private subnets for nodes; public subnet only for load balancers
- Security groups: nodes accept inbound only from ALB SGs and control plane SG
- Kubernetes NetworkPolicy (Calico/Cilium): default deny, explicit allow
- No node-to-node unrestricted traffic

**2. Access Control:**
- EKS OIDC provider configured; developers authenticate via SSO (not IAM static keys)
- IRSA for pod identities (no long-lived IAM access keys in pods)
- RBAC: least-privilege, namespace-scoped, GitOps-managed
- `cluster-admin` access via break-glass IAM role, time-limited

**3. Encryption:**
- etcd encryption at rest: KMS provider backed by AWS KMS with CMK
- EBS volumes encrypted with CMK
- All traffic in transit: TLS (mTLS for control-plane components)
- Secrets in AWS Secrets Manager via External Secrets Operator (not K8s Secrets)

**4. Audit:**
- CloudTrail for AWS API calls (IAM, EKS control plane logs)
- K8s audit log: API server logs to CloudWatch Logs with appropriate retention
- VPC Flow Logs: all node traffic captured

**5. Image Security:**
- ECR with image scanning; block deployment of HIGH/CRITICAL CVEs (Kyverno policy)
- Image signing via Cosign + Kyverno policy to verify signatures

**6. Runtime:**
- Falco DaemonSet for runtime threat detection
- Seccomp RuntimeDefault on all pods
- No privileged containers (enforced by Kyverno)

**7. CIS Benchmark:** Run kube-bench post-provisioning; remediate all FAIL items.

**What the interviewer is looking for:** Comprehensive coverage, awareness of PCI requirements, practical EKS-specific implementation (IRSA, ECR, KMS CMK), not just generic K8s hardening.

---

### Q3: How does kube-bench work, and what are its limitations?

**Model Answer:**

kube-bench is an open-source Go tool by Aqua Security that runs the CIS Kubernetes Benchmark checks against a cluster. It inspects:
- Running process arguments (via `/proc/<pid>/cmdline`) for kube-apiserver, kubelet, etc.
- Configuration files and their permissions/ownership
- RBAC bindings and policies

It runs as a Kubernetes Job or DaemonSet, with targets for `master`, `node`, `etcd`, `policies`.

**Limitations:**
1. **Static configuration checks only** — cannot assess runtime behavior (e.g., whether a NetworkPolicy is actually enforced by the CNI)
2. **Node-level access required** — must run on each node; remote scanning is not possible for most checks
3. **Managed K8s limitations** — on EKS/GKE/AKS, the control plane is managed; many API server checks cannot run (the control plane host is not accessible)
4. **Point-in-time snapshot** — does not continuously monitor for drift
5. **No severity weighting** — all FAILs look the same; not all are equally critical
6. **CNI/CSI awareness** — does not check CNI plugin configuration for NetworkPolicy enforcement
7. **Custom policies not covered** — OPA/Kyverno policies are outside scope

**Complement kube-bench with:**
- `Trivy k8s` for image vulnerabilities + RBAC misconfigs
- `Polaris` for workload best practices
- `Falco` for runtime detection
- `OPA/Gatekeeper` for continuous policy enforcement (not just auditing)

**What the interviewer is looking for:** Knows the tool practically, not just conceptually; can articulate what it does NOT cover.

---

### Q4: Explain how you would design network segmentation for a cluster with 5 teams sharing it.

**Model Answer:**

**Namespace-per-team with defense-in-depth network controls:**

1. **Namespace labels** for NetworkPolicy selectors:
```yaml
metadata:
  labels:
    team: payments
    env: prod
```

2. **Default-deny policy** applied to every namespace by platform team (via Kyverno ClusterPolicy):
```yaml
# Kyverno generate policy: auto-create default-deny in new namespaces
```

3. **Intra-team communication:** Allow within namespace using podSelector only

4. **Cross-team communication:** Explicit NetworkPolicy with `namespaceSelector` — team must open an explicit port. Document as "network contracts" in a service catalog.

5. **Shared services (monitoring, logging):** Allow egress from all namespaces to monitoring namespace on specific ports (9090 Prometheus, 9200 Elasticsearch). Enforced by a ClusterNetworkPolicy if using Cilium.

6. **Egress to external:** Explicit egress NetworkPolicy. Internet egress goes through an egress proxy (Squid/Envoy), not directly from pod.

7. **Enforcement verification:** Regularly test with `kubectl exec` network tests or tools like `netassert` or `connectivity-check`.

8. **Observability:** Cilium Hubble or Calico flow logs to visualize inter-namespace traffic — essential for detecting policy gaps.

**What the interviewer is looking for:** Practical multi-tenant design, not just "create NetworkPolicies" — mentions automation, observability, and escape hatches for shared services.

---

### Q5: What is the CIS Kubernetes Benchmark Level 1 vs Level 2, and which controls do you always implement?

**Model Answer:**

**Level 1:** "Practical and prudent" — items that can be implemented in most environments without significant impact on functionality. These are baseline security hygiene.

**Level 2:** "Defense in depth" — items that may have greater operational impact, require deeper expertise, or restrict functionality that some organizations require. These are optional but recommended for high-security environments.

**Always implement (Level 1 baseline):**
- `--anonymous-auth=false` on API server and kubelet (CIS 1.2.1, 4.2.1)
- `--authorization-mode=Node,RBAC` (CIS 1.2.7)
- `--audit-log-path` set (CIS 1.2.16)
- `--service-account-lookup=true` (CIS 1.2.24)
- `--client-cert-auth=true` on etcd (CIS 2.2)
- `--read-only-port=0` on kubelet (CIS 4.2.4)
- `--rotate-certificates=true` on kubelet (CIS 4.2.11)

**Implement for sensitive workloads (Level 2):**
- etcd encryption at rest (CIS 1.2.32)
- Audit at `RequestResponse` level for security events
- Seccomp `RuntimeDefault` enforced cluster-wide (CIS 5.7.2)
- Pod Security Admission `restricted` profile on workload namespaces

**What I always prioritize beyond CIS:**
- OPA/Gatekeeper or Kyverno for continuous enforcement (CIS is audit, not enforcement)
- Falco for runtime detection (CIS doesn't cover runtime)
- Image scanning + signing (supply chain is CIS's weakest coverage area)

**What the interviewer is looking for:** Knows L1 vs L2 distinction, has genuine opinions about prioritization, understands CIS as baseline not ceiling.

---

### Q6: How do you handle the tension between security hardening and developer productivity in a platform team?

**Model Answer:**

This is a real friction point. My approach:

**1. Shift from gate to guardrail:** Replace hard blocks with `warn` mode first. Pod Security Admission's `warn` mode tells developers what to fix without breaking their workflow. Kyverno `audit` mode generates reports without blocking.

**2. Provide secure defaults (paved road):** Golden templates (Helm charts, Kustomize bases) that already comply with policies. Developers instantiate the template — security is built-in, not bolted on.

**3. Self-service with policy:** Let developers do what they need, within bounds. Example: developers can `kubectl exec` in dev/staging namespaces but not in production — the policy enforces the right behavior at the right time.

**4. Explain the "why":** When a policy blocks a deploy, the error message should link to a runbook explaining why and how to fix it. Generic "policy violation" errors create frustration.

**5. Progressive enforcement:** New clusters start strict; existing clusters migrate with a timeline and tooling support. Never enforce new policies on existing workloads without a migration plan.

**6. Developer advocacy loop:** Platform team runs a monthly "security friction review" — if the same policy is being bypassed repeatedly, it's a signal the policy is wrong, not the developers.

**Specific examples:**
- `seccompProfile` → add to Helm chart base template
- `readOnlyRootFilesystem` → developers add an `emptyDir` for their write paths (documented pattern)
- Image signing → automated in CI pipeline, transparent to developers

**What the interviewer is looking for:** Maturity about organizational change, not just technical hardening; developer empathy combined with non-negotiable security outcomes.

---

### Q7: What is etcd peer TLS vs client TLS, and why do you need both?

**Model Answer:**

etcd has two distinct TLS communication channels:

**Client TLS (port 2379):** Secures communication between etcd and its clients — primarily the kube-apiserver. This ensures:
- The API server is authenticated to etcd (using a client cert)
- etcd traffic cannot be intercepted by a third party
- Only authorized clients (API server) can read/write cluster state

Flags: `--cert-file`, `--key-file`, `--trusted-ca-file`, `--client-cert-auth=true`

**Peer TLS (port 2380):** Secures communication between etcd cluster members (in an HA 3-node or 5-node etcd cluster). This ensures:
- No rogue etcd node can join the cluster
- Raft consensus protocol is encrypted
- etcd cluster splits cannot be induced by network injection

Flags: `--peer-cert-file`, `--peer-key-file`, `--peer-client-cert-auth=true`

**Why both?** A compromised internal network (lateral movement post-breach) could:
- Without client TLS: read all secrets directly from etcd without going through the API server
- Without peer TLS: inject a fake etcd peer and corrupt the Raft log, causing a cluster split or data poisoning

In high-security environments, use **separate CAs** for etcd and the cluster: one for API server client certs (`kubernetes-ca`) and one for etcd (`etcd-ca`). This limits blast radius — compromise of the kubernetes-ca does not give etcd access.

**What the interviewer is looking for:** Understands the two distinct TLS channels, can articulate the threat model each addresses.

---

### Q8: How do you prevent privilege escalation through RBAC in a large multi-team cluster?

**Model Answer:**

Multiple complementary controls:

**1. Restrict RBAC management itself:**
- Only the platform team (`system:masters` break-glass or a dedicated `rbac-admin` group) can create ClusterRoleBindings
- Teams can create RoleBindings within their namespace but only to pre-approved ClusterRoles
- Enforced by Kyverno: `ClusterRoleBindings` require approval annotation + label

**2. Block the escalation verbs:**
```yaml
# OPA/Gatekeeper ConstraintTemplate: deny 'escalate' and 'bind' verbs for non-admins
# Deny 'impersonate' outside the platform team namespace
```

**3. No wildcard rules:**
- Kyverno policy: reject any Role/ClusterRole with `verbs: ["*"]` or `resources: ["*"]`
- Makes exceptions require explicit bypass (audit trail)

**4. GitOps for RBAC:**
- All RoleBindings and ClusterRoles stored in Git
- Changes require PR review by platform team
- ArgoCD sync detects drift and alerts (or reverts)

**5. Continuous audit:**
- Weekly automated scan: `kubectl auth can-i --list` for all service accounts with cluster-wide permissions
- Alert on new ClusterRoleBindings to `cluster-admin`
- Alert on any use of `impersonate` in audit logs

**6. Time-bounded elevation:**
- Use `kube-escalator` or Teleport's `kubectl access request` for temporary privilege elevation
- Approved via Slack/PagerDuty, auto-revoked after TTL

**What the interviewer is looking for:** Defense-in-depth approach — not one mechanism but a combination of GitOps, policy engine, audit, and process controls.

---

### Q9: What are RuntimeClasses, and when would you use Kata Containers over runc?

**Model Answer:**

`RuntimeClass` is a Kubernetes resource that maps a pod to a specific container runtime configuration. It allows running pods with different isolation levels on the same cluster.

```yaml
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: kata-containers
handler: kata-containers    # Must match containerd runtime handler name
overhead:
  podFixed:
    memory: "140Mi"
    cpu: "250m"
scheduling:
  nodeSelector:
    runtime: kata           # Only schedule on nodes with Kata installed
```

**runc (default):** Traditional OCI runtime. Containers share the host kernel. Fast (sub-millisecond overhead), lowest resource usage.

**Kata Containers:** Each pod gets a lightweight VM with its own kernel (based on QEMU/KVM or Firecracker). Containers inside the VM are isolated from the host kernel.

**When to use Kata:**
1. Running untrusted third-party code (user-submitted containers in FaaS/PaaS)
2. Multi-tenant hosting where tenants should have kernel isolation
3. Processing highly sensitive data where a container escape would be catastrophic
4. Compliance requirements that mandate VM-level isolation (some financial regulators)

**When NOT to use Kata:**
- Performance-sensitive workloads (Kata adds 100-200ms startup time, increased memory)
- Storage I/O-intensive workloads (virtio adds overhead)
- When soft tenancy is adequate (most enterprise multi-team scenarios)

**Alternative:** gVisor (`runsc`) — intercepts syscalls in userspace (no full VM), lighter than Kata but more compatible with runc than Kata.

**What the interviewer is looking for:** Knows RuntimeClass as the integration point, can articulate the Kata threat model (kernel isolation) vs performance tradeoff.

---

### Q10: Describe your incident response process for a suspected container escape on a Kubernetes node.

**Model Answer:**

**Immediate containment (T+0 to T+15 min):**
```bash
# 1. Cordon the node immediately (prevent new scheduling)
kubectl cordon <compromised-node>

# 2. Identify suspicious pods/processes
kubectl get pods -A --field-selector=spec.nodeName=<compromised-node>

# 3. Check recent Falco alerts on this node
kubectl logs -n falco ds/falco --since=1h | grep <node-name>

# 4. If container escape confirmed: drain + isolate the node
# Option A: drain (graceful workload migration)
kubectl drain <compromised-node> --ignore-daemonsets --delete-emptydir-data

# Option B: if too risky to drain (might spread compromise): terminate immediately
# (AWS: terminate EC2 instance; GCP: delete VM; Azure: deallocate VM)
```

**Investigation (T+15 min to T+2 hours):**
```bash
# 5. Capture node memory image before termination (if forensics required)
# Use cloud snapshot of the root EBS volume

# 6. Pull audit logs for the node and related service accounts
kubectl get events --field-selector=involvedObject.kind=Pod \
  --field-selector=involvedObject.namespace=<namespace> --sort-by='.lastTimestamp'

# 7. Check for lateral movement via audit log
grep '"sourceIPs":\["<node-ip>"' /var/log/kubernetes/audit.log

# 8. Identify affected service account tokens (they may be stolen)
kubectl get pod <pod> -o jsonpath='{.spec.serviceAccountName}'
# Rotate the SA token: delete the SA and recreate, or use token revocation (K8s 1.26+)

# 9. Check for persistence: new ClusterRoleBindings, new SA, DaemonSets
kubectl get clusterrolebindings --sort-by='.metadata.creationTimestamp' | tail -20
kubectl get serviceaccounts -A --sort-by='.metadata.creationTimestamp' | tail -20
```

**Remediation:**
1. Rotate all service account tokens that ran on the node
2. Rotate etcd encryption keys if node had etcd access
3. Replace the node with a fresh image (immutable infrastructure)
4. Conduct root cause analysis: which vulnerability allowed the escape?
5. Apply patch or policy mitigation before bringing new node online

**What the interviewer is looking for:** Incident response is a process, not just technical steps; containment before investigation; token rotation as a key step; audit log as evidence source.

---

### Q11: How do you audit Secrets management in a Kubernetes cluster — what are the security gaps in native K8s Secrets?

**Model Answer:**

**Native K8s Secrets limitations:**

1. **Base64 ≠ encryption:** Without EncryptionConfiguration, Secrets are stored in plaintext base64 in etcd. Anyone with etcd read access gets all secrets.

2. **Over-broad RBAC access:** Default `view` and `edit` roles do NOT include secrets, but custom roles often inadvertently grant `secrets:list` cluster-wide.

3. **Environment variable injection risk:** Secrets mounted as env vars are visible in `kubectl describe pod`, in `/proc/<pid>/environ`, and in some logging configurations that capture env vars.

4. **No versioning or rotation tracking:** K8s Secrets have no built-in rotation detection or access audit trail (only API server audit log).

5. **Backup exposure:** etcd backups contain all secrets; backups are often not encrypted.

6. **No dynamic secrets:** K8s Secrets are static; database credentials stored as Secrets are not rotated automatically.

**Auditing approach:**
```bash
# Find all pods mounting secrets as env vars (risk of logging exposure)
kubectl get pods -A -o json | jq -r '
  .items[] | 
  select(.spec.containers[].env[]?.valueFrom.secretKeyRef != null) |
  .metadata.namespace + "/" + .metadata.name'

# Find secrets accessible cluster-wide
kubectl auth can-i list secrets -A --as=system:serviceaccount:prod:my-app

# Find any service accounts with wildcard secret access
kubectl get clusterroles -o json | jq -r '
  .items[] | 
  select(.rules[]? | (.resources[]? == "secrets" or .resources[]? == "*") and (.verbs[]? == "list" or .verbs[]? == "*")) |
  .metadata.name'
```

**Better approaches:**
- External Secrets Operator + AWS Secrets Manager / GCP Secret Manager / HashiCorp Vault
- Vault Agent Injector (sidecar injects secrets, never stored in K8s)
- Sealed Secrets (Bitnami) — GitOps-friendly encrypted secrets

**What the interviewer is looking for:** Knows specific technical limitations, has practical audit commands, can recommend better architectures.

---

### Q12: What are the security implications of `hostNetwork: true`, `hostPID: true`, and `hostIPC: true`, and when are they legitimate?

**Model Answer:**

These pod spec options break the namespace isolation provided by Linux kernel namespaces.

**`hostNetwork: true`:**
- Pod joins the host network namespace
- Can bind to any port on the node IP (including privileged ports <1024)
- Can sniff all node network traffic
- Can reach internal node services (e.g., cloud metadata endpoints `169.254.169.254`)
- Cloud metadata SSRF risk: if an attacker controls the pod, they can steal the EC2/GCE instance credentials
- **Legitimate use:** Network-sensitive DaemonSets (Calico, Cilium, kube-proxy, metrics exporters)

**`hostPID: true`:**
- Pod can see all processes on the host
- Can read `/proc/<pid>/environ` of host processes (credential leakage)
- Can send signals to host processes
- Can ptrace host processes (if also privileged)
- **Legitimate use:** Very narrow — some security tools (Falco with eBPF can avoid it), some debuggers, `node-problem-detector`

**`hostIPC: true`:**
- Pod can access host inter-process communication (shared memory, semaphores)
- Can read shared memory of other host processes
- Can attach to container runtime's IPC namespace
- **Legitimate use:** High-performance computing (HPC) workloads, some databases

**Detection and prevention:**
```yaml
# Kyverno ClusterPolicy: block all three unless exempted
spec:
  rules:
    - name: restrict-host-namespaces
      match:
        resources:
          kinds: [Pod]
      validate:
        message: "hostNetwork, hostPID, and hostIPC are not allowed"
        pattern:
          spec:
            =(hostNetwork): "false"
            =(hostPID): "false"
            =(hostIPC): "false"
```

**What the interviewer is looking for:** Technical understanding of what each flag does at the kernel level (not just "it's dangerous"), awareness of SSRF via cloud metadata, legitimate use cases, policy enforcement.

---

## 12. References

| Resource | URL |
|---|---|
| CIS Kubernetes Benchmark | https://www.cisecurity.org/benchmark/kubernetes |
| NSA/CISA Kubernetes Hardening Guide | https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF |
| NIST SP 800-190 (Container Security) | https://csrc.nist.gov/publications/detail/sp/800-190/final |
| Kubernetes Security Checklists | https://kubernetes.io/docs/concepts/security/security-checklist/ |
| Pod Security Admission | https://kubernetes.io/docs/concepts/security/pod-security-admission/ |
| Kubernetes Network Policy | https://kubernetes.io/docs/concepts/services-networking/network-policies/ |
| etcd Security | https://etcd.io/docs/v3.5/op-guide/security/ |
| kube-bench | https://github.com/aquasecurity/kube-bench |
| Trivy k8s | https://trivy.dev/latest/docs/target/kubernetes/ |
| Polaris (Fairwinds) | https://github.com/FairwindsOps/polaris |
| Falco | https://falco.org/docs/ |
| OPA/Gatekeeper | https://open-policy-agent.github.io/gatekeeper/ |
| Kyverno | https://kyverno.io/docs/ |
| vCluster | https://www.vcluster.com/docs/ |
| Cilium NetworkPolicy | https://docs.cilium.io/en/stable/network/kubernetes/policy/ |
| External Secrets Operator | https://external-secrets.io/latest/ |
| Kata Containers | https://katacontainers.io/ |
| MITRE ATT&CK for Containers | https://attack.mitre.org/matrices/enterprise/containers/ |
