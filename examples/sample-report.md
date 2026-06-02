# EKS Log Analysis Report

## Summary

- **Generated:** 2026-06-01T21:17:14.227148-07:00
- **Log directory:** `tests\fixtures\sample-export`
- **Files scanned:** 8
- **Events parsed:** 36
- **Findings:** 11
- **By severity:** 🔴 1 critical, 🟠 7 high, 🟡 3 medium
- **First signal:** 2024-05-01T12:00:06.310000+00:00 — `aws-node.log:3` (cni-ip-exhaustion)

## Timeline

Cross-source ordering of notable events (from finding evidence).

| Time (UTC) | Source | Finding | Location | Event |
|------------|--------|---------|----------|-------|
| 2024-05-01T12:00:06.310000+00:00 ⭐ | aws-node | cni-ip-exhaustion | `aws-node.log:3` | 2024-05-01T12:00:06.310Z [ERROR] ipamd: no available IP addresses in datastore |
| 2024-05-01T12:00:06.450000+00:00 | aws-node | cni-ip-exhaustion | `aws-node.log:4` | 2024-05-01T12:00:06.450Z [ERROR] failed to assign an IP address to container eni-aaaa1111 |
| 2024-05-01T12:00:07.001000+00:00 | aws-node | api-throttling | `aws-node.log:5` | 2024-05-01T12:00:07.001Z [WARN] RequestLimitExceeded calling DescribeNetworkInterfaces, backing off |
| 2024-05-01T12:00:09.500000+00:00 | aws-node | cni-ip-exhaustion | `aws-node.log:6` | 2024-05-01T12:00:09.500Z [ERROR] unable to allocate ENI: insufficient IP addresses available |
| 2024-05-01T12:00:09.500000+00:00 | aws-node | cni-aws-node | `aws-node.log:6` | 2024-05-01T12:00:09.500Z [ERROR] unable to allocate ENI: insufficient IP addresses available |
| 2024-05-01T12:00:12.500000+00:00 | kube-proxy | api-throttling | `kube-proxy.log:2` | E0501 12:00:12.500000       1 reflector.go:138] "Throttling request took 4.5s, request: GET https://10.100.0.1:443/ap… |
| 2024-05-01T12:00:25.900000+00:00 | pod | dns-failure | `pods/default_web-7c_app.log:3` | 2024-05-01T12:00:25.900Z dial tcp: lookup db.example.internal: no such host |
| 2024-05-01T12:00:30.654321+00:00 | kubelet | kubelet-pleg | `kubelet.log:2` | I0501 12:00:30.654321    1234 kubelet.go:2456] "PLEG is not healthy: pleg has yet to be successful" |
| 2024-05-01T12:00:31.111111+00:00 | kubelet | kubelet-disk-pressure | `kubelet.log:3` | W0501 12:00:31.111111    1234 eviction_manager.go:340] "Eviction manager: attempting to reclaim ephemeral-storage" |
| 2024-05-01T12:00:31.222222+00:00 | kubelet | kubelet-disk-pressure | `kubelet.log:4` | W0501 12:00:31.222222    1234 helpers.go:781] "DiskPressure condition observed on node ip-10-0-1-23" |
| 2024-05-01T12:00:40+00:00 | dmesg | kubelet-memory-pressure | `dmesg.log:1` | May  1 12:00:40 ip-10-0-1-23 kernel: Memory cgroup out of memory: Killed process 4567 (java) total-vm:2097152kB |
| 2024-05-01T12:00:40+00:00 | dmesg | container-oomkilled | `dmesg.log:1` | May  1 12:00:40 ip-10-0-1-23 kernel: Memory cgroup out of memory: Killed process 4567 (java) total-vm:2097152kB |
| 2024-05-01T12:00:40+00:00 | dmesg | container-oomkilled | `dmesg.log:2` | May  1 12:00:40 ip-10-0-1-23 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null) |
| 2024-05-01T12:00:41+00:00 | dmesg | kubelet-memory-pressure | `dmesg.log:3` | May  1 12:00:41 ip-10-0-1-23 kernel: System OOM encountered, victim process: python3 |
| 2024-05-01T12:00:44.900000+00:00 | containerd | image-pull-failure | `containerd.log:1` | time="2024-05-01T12:00:44.900Z" level=error msg="failed to pull image \"myrepo/app:latest\": manifest unknown" |
| 2024-05-01T12:00:45.333333+00:00 | kubelet | image-pull-failure | `kubelet.log:5` | E0501 12:00:45.333333    1234 kuberuntime_manager.go:1256] "Failed to pull image \"myrepo/app:latest\": ErrImagePull:… |
| 2024-05-01T12:00:46+00:00 | events | image-pull-failure | `describe-events.txt:2` | 2024-05-01T12:00:46Z  Warning  Failed       kubelet  Failed to pull image "myrepo/app:latest": ErrImagePull |
| 2024-05-01T12:00:46.444444+00:00 | kubelet | image-pull-failure | `kubelet.log:6` | E0501 12:00:46.444444    1234 pod_workers.go:965] "Error syncing pod" err="ImagePullBackOff" |
| 2024-05-01T12:00:47+00:00 | events | image-pull-failure | `describe-events.txt:3` | 2024-05-01T12:00:47Z  Warning  BackOff      kubelet  Back-off pulling image -> ImagePullBackOff |
| 2024-05-01T12:00:50+00:00 | messages | container-oomkilled | `messages.log:1` | May  1 12:00:50 ip-10-0-1-23 dockerd[900]: container 9f2a OOMKilled (memory limit exceeded) |
| 2024-05-01T12:01:01.555555+00:00 | kubelet | tls-x509 | `kubelet.log:7` | E0501 12:01:01.555555    1234 remote_runtime.go:294] "x509: certificate has expired or is not yet valid" |
| 2024-05-01T12:01:02+00:00 | containerd | tls-x509 | `containerd.log:3` | time="2024-05-01T12:01:02.000Z" level=error msg="x509: certificate signed by unknown authority" |
| 2024-05-01T12:01:20.666666+00:00 | kubelet | ebs-csi-mount | `kubelet.log:8` | E0501 12:01:20.666666    1234 reconciler.go:201] "FailedMount: unable to attach or mount volumes: timed out waiting f… |
| 2024-05-01T12:01:21+00:00 | events | ebs-csi-mount | `describe-events.txt:4` | 2024-05-01T12:01:21Z  Warning  FailedMount  kubelet  MountVolume.SetUp failed: Multi-Attach error for volume vol-0abc |

⭐ = first signal.

## Findings

### 🔴 `cni-ip-exhaustion` — VPC CNI IP address exhaustion

- **Severity:** critical
- **Matches:** 3
- **What it means:** The VPC CNI could not allocate a pod IP. Usually the subnet/ENI IP pool is exhausted or WARM_IP_TARGET is too low for pod density.

**Evidence:**

```text
aws-node.log:3: 2024-05-01T12:00:06.310Z [ERROR] ipamd: no available IP addresses in datastore
aws-node.log:4: 2024-05-01T12:00:06.450Z [ERROR] failed to assign an IP address to container eni-aaaa1111
aws-node.log:6: 2024-05-01T12:00:09.500Z [ERROR] unable to allocate ENI: insufficient IP addresses available
```

### 🟠 `container-oomkilled` — Container OOMKilled

- **Severity:** high
- **Matches:** 3
- **What it means:** A container exceeded its memory limit and was killed by the OOM killer.

**Evidence:**

```text
dmesg.log:1: May  1 12:00:40 ip-10-0-1-23 kernel: Memory cgroup out of memory: Killed process 4567 (java) total-vm:2097152kB
dmesg.log:2: May  1 12:00:40 ip-10-0-1-23 kernel: oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null)
messages.log:1: May  1 12:00:50 ip-10-0-1-23 dockerd[900]: container 9f2a OOMKilled (memory limit exceeded)
```

### 🟠 `ebs-csi-mount` — EBS volume mount failure

- **Severity:** high
- **Matches:** 2
- **What it means:** A pod could not mount its EBS volume, often Multi-Attach conflicts, AZ mismatch, or the EBS CSI driver lacking permissions.

**Evidence:**

```text
describe-events.txt:4: 2024-05-01T12:01:21Z  Warning  FailedMount  kubelet  MountVolume.SetUp failed: Multi-Attach error for volume vol-0abc
kubelet.log:8: E0501 12:01:20.666666    1234 reconciler.go:201] "FailedMount: unable to attach or mount volumes: timed out waiting for vol-0abc"
```

### 🟠 `kubelet-disk-pressure` — Node disk pressure / eviction

- **Severity:** high
- **Matches:** 2
- **What it means:** The kubelet detected DiskPressure and may be evicting pods or garbage collecting images to reclaim space.

**Evidence:**

```text
kubelet.log:3: W0501 12:00:31.111111    1234 eviction_manager.go:340] "Eviction manager: attempting to reclaim ephemeral-storage"
kubelet.log:4: W0501 12:00:31.222222    1234 helpers.go:781] "DiskPressure condition observed on node ip-10-0-1-23"
```

### 🟠 `kubelet-memory-pressure` — Node memory pressure

- **Severity:** high
- **Matches:** 2
- **What it means:** The node is under memory pressure; the kubelet may evict pods and the kernel OOM killer may terminate processes.

**Evidence:**

```text
dmesg.log:1: May  1 12:00:40 ip-10-0-1-23 kernel: Memory cgroup out of memory: Killed process 4567 (java) total-vm:2097152kB
dmesg.log:3: May  1 12:00:41 ip-10-0-1-23 kernel: System OOM encountered, victim process: python3
```

### 🟠 `tls-x509` — TLS / x509 certificate error

- **Severity:** high
- **Matches:** 2
- **What it means:** A TLS handshake failed due to an expired, untrusted, or invalid certificate (kubelet client cert, API server CA, or registry TLS).

**Evidence:**

```text
containerd.log:3: time="2024-05-01T12:01:02.000Z" level=error msg="x509: certificate signed by unknown authority"
kubelet.log:7: E0501 12:01:01.555555    1234 remote_runtime.go:294] "x509: certificate has expired or is not yet valid"
```

### 🟠 `cni-aws-node` — aws-node / IPAMD configuration failure

- **Severity:** high
- **Matches:** 1
- **What it means:** The aws-node (VPC CNI) daemonset failed to configure pod networking or its IPAM datastore reported an error.

**Evidence:**

```text
aws-node.log:6: 2024-05-01T12:00:09.500Z [ERROR] unable to allocate ENI: insufficient IP addresses available
```

### 🟠 `kubelet-pleg` — PLEG (Pod Lifecycle Event Generator) unhealthy

- **Severity:** high
- **Matches:** 1
- **What it means:** The kubelet's PLEG could not relist container state in time, often caused by an overloaded or unresponsive container runtime.

**Evidence:**

```text
kubelet.log:2: I0501 12:00:30.654321    1234 kubelet.go:2456] "PLEG is not healthy: pleg has yet to be successful"
```

### 🟡 `image-pull-failure` — Image pull failure

- **Severity:** medium
- **Matches:** 5
- **What it means:** The runtime could not pull a container image (auth, missing tag, or registry/network problem).

**Evidence:**

```text
containerd.log:1: time="2024-05-01T12:00:44.900Z" level=error msg="failed to pull image \"myrepo/app:latest\": manifest unknown"
describe-events.txt:2: 2024-05-01T12:00:46Z  Warning  Failed       kubelet  Failed to pull image "myrepo/app:latest": ErrImagePull
describe-events.txt:3: 2024-05-01T12:00:47Z  Warning  BackOff      kubelet  Back-off pulling image -> ImagePullBackOff
kubelet.log:5: E0501 12:00:45.333333    1234 kuberuntime_manager.go:1256] "Failed to pull image \"myrepo/app:latest\": ErrImagePull: pull access denied"
kubelet.log:6: E0501 12:00:46.444444    1234 pod_workers.go:965] "Error syncing pod" err="ImagePullBackOff"
```

### 🟡 `api-throttling` — AWS API throttling

- **Severity:** medium
- **Matches:** 2
- **What it means:** AWS API calls are being throttled, which can stall ENI/IP allocation and other control operations.

**Evidence:**

```text
aws-node.log:5: 2024-05-01T12:00:07.001Z [WARN] RequestLimitExceeded calling DescribeNetworkInterfaces, backing off
kube-proxy.log:2: E0501 12:00:12.500000       1 reflector.go:138] "Throttling request took 4.5s, request: GET https://10.100.0.1:443/api/v1/endpoints"
```

### 🟡 `dns-failure` — DNS resolution failure (CoreDNS/kube-dns)

- **Severity:** medium
- **Matches:** 1
- **What it means:** DNS lookups are failing, often pointing at CoreDNS health, kube-proxy rules, or NodeLocal DNS issues.

**Evidence:**

```text
pods/default_web-7c_app.log:3: 2024-05-01T12:00:25.900Z dial tcp: lookup db.example.internal: no such host
```


## Suggested checks

**`cni-ip-exhaustion`**
- [ ] Check free IPs in the node's subnets and ENI limits for the instance type.
- [ ] Review aws-node env: WARM_IP_TARGET, MINIMUM_IP_TARGET, ENABLE_PREFIX_DELEGATION.
- [ ] Consider prefix delegation or larger/secondary subnets.

**`container-oomkilled`**
- [ ] Raise the container memory limit or fix the leak.
- [ ] kubectl describe pod <pod> and check lastState.terminated.reason.

**`ebs-csi-mount`**
- [ ] Ensure the pod is scheduled in the volume's AZ.
- [ ] Check the EBS CSI driver pods and the node role's EBS permissions.

**`kubelet-disk-pressure`**
- [ ] df -h on the node; inspect /var/lib/containerd and /var/log.
- [ ] Check image/log growth and eviction thresholds (--eviction-hard).

**`kubelet-memory-pressure`**
- [ ] Check node allocatable vs requests; look for memory leaks.
- [ ] Review pod memory limits and node instance sizing.

**`tls-x509`**
- [ ] Check kubelet client cert rotation and node clock skew (NTP).
- [ ] Verify the cluster CA bundle and any custom registry CAs.

**`cni-aws-node`**
- [ ] kubectl -n kube-system logs ds/aws-node -c aws-node
- [ ] Confirm the CNI version is compatible with the cluster Kubernetes version.
- [ ] Check the node IAM role has the AmazonEKS_CNI_Policy permissions.

**`kubelet-pleg`**
- [ ] Check containerd health and CPU/IO saturation on the node.
- [ ] Look for a flood of containers or a stuck image pull.
- [ ] kubectl describe node and check for NotReady transitions.

**`image-pull-failure`**
- [ ] Verify the image tag exists and the registry is reachable.
- [ ] For ECR, confirm the node role has ecr:GetAuthorizationToken + pull perms.

**`api-throttling`**
- [ ] Reduce API call rate; check for tight reconcile loops.
- [ ] Request a service quota increase if sustained.

**`dns-failure`**
- [ ] kubectl -n kube-system get pods -l k8s-app=kube-dns
- [ ] Test resolution from a debug pod: nslookup kubernetes.default.

