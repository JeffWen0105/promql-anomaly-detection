# RHEL 8 / RHEL 9 AI Dynamic Anomaly Detection — Design Rationale

This document explains **why** each metric in
`rules/examples/rhel89_node_exporter.yml` is monitored, what signal it
provides for RHEL 8/9 systems, and which literature or specifications
support the choice.

---

## Framework overview

The file hooks into the existing **adaptive** and **robust** strategy
engines without requiring any change to the core rule files
(`adaptive.yml`, `robust.yml`).  Every recording rule simply attaches
the labels `anomaly_name`, `anomaly_type`, and `anomaly_strategy` to a
derived metric so it is automatically ingested by the framework.

### Strategy guidance

| Strategy | Best for | RHEL 8/9 use case |
|----------|----------|-------------------|
| `adaptive` | Normally-distributed, time-varying signals | CPU %, memory %, network throughput — metrics that follow business-hour patterns |
| `robust` | Spiky / non-normal signals; slow drift | Context switches, disk I/O, filesystem fill — metrics with heavy tails or monotonic growth |

Both strategies are provided for every metric so operators can choose
per-use-case without duplicating PromQL.

### node_exporter default collectors used

All metrics below are exposed by node_exporter with **no extra flags**.
The following default-enabled collectors are used:

| Collector | Metrics prefix | RHEL note |
|-----------|---------------|-----------|
| `cpu` | `node_cpu_seconds_total` | RHEL 8/9 reports all CPU modes including `steal` for VMs |
| `meminfo` | `node_memory_*` | Parses `/proc/meminfo`; `MemAvailable` available since kernel 3.14 (RHEL 7+) |
| `diskstats` | `node_disk_*` | Parses `/proc/diskstats`; includes dm- (LVM) devices |
| `filesystem` | `node_filesystem_*` | XFS is RHEL 8/9 default; ext4 also supported |
| `netdev` | `node_network_*` | Parses `/proc/net/dev` |
| `loadavg` | `node_load*` | `/proc/loadavg`; includes I/O wait in load count |
| `stat` | `node_context_switches_total` | `/proc/stat` |

---

## Monitored targets

### 1. CPU Utilisation (%)

**PromQL signal:** `1 - rate(node_cpu_seconds_total{mode="idle"}[5m])` × 100

**Why monitor it?**

CPU saturation is the most fundamental indicator of compute health.  An
anomalous rise in CPU usage indicates runaway processes, unexpected batch
jobs, cryptomining malware, or legitimate workload spikes that require
capacity action.

On **RHEL 8/9 virtualised deployments** the `steal` mode (CPU cycles
stolen by the hypervisor) can cause latency spikes invisible to
application-level metrics.  Because we aggregate *all* non-idle modes in
a single series the steal component is included automatically.

**Why anomaly detection rather than a fixed threshold?**

Workload-dependent CPU baselines vary enormously between environments and
even between time-of-day windows.  A fixed threshold of, say, 80 % would
generate constant alerts on a batch-oriented host and miss a real incident
on an idle host whose normal usage is 5 %.  The adaptive strategy's
1 h average ± 2 σ (smoothed over 26 h) self-calibrates to each host's
actual pattern.

**Literature / specifications:**

- B. Gregg, *Systems Performance: Enterprise and the Cloud*, 2nd ed.
  Pearson, 2020.  Chapter 6 (CPUs) — USE Method (Utilisation, Saturation,
  Errors).
- Red Hat, *Performance Tuning Guide for RHEL 8*,
  <https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/index>
- NIST SP 800-137, *Information Security Continuous Monitoring (ISCM)*,
  2011 — recommends automated anomaly detection for system resources.

---

### 2. Memory Utilisation (%)

**PromQL signal:** `1 - MemAvailable / MemTotal` × 100

**Why `MemAvailable` instead of `MemFree`?**

`MemFree` counts only completely unused pages.  `MemAvailable` is a
kernel estimate (introduced in Linux 3.14 / RHEL 7+) of how much memory
can be freed without swapping, including reclaimable page-cache and slab
memory.  This matches the semantics of `free -h` and accurately reflects
the memory actually available to new workloads.

**Why monitor it?**

Memory exhaustion triggers the Out-Of-Memory (OOM) killer, which
terminates processes non-deterministically.  On RHEL 8/9 with
`memory.use_hierarchy` cgroups v1 (RHEL 8) or cgroups v2 (RHEL 9 default
since kernel 5.14), memory pressure can be confined to a cgroup yet
aggregate memory still fills up, causing silent cgroup-level OOM kills
that are hard to detect without system-level monitoring.

Anomaly detection catches gradual memory leaks that would be missed by
fixed-threshold alerts until the situation becomes critical.

**Literature:**

- Linux kernel documentation, `proc(5)`, `/proc/meminfo` field
  descriptions — <https://www.kernel.org/doc/html/latest/filesystems/proc.html>
- B. Gregg, *Systems Performance*, 2nd ed., Chapter 7 (Memory).
- D. Andersen et al., "DRAM Errors in the Wild: A Large-Scale Field
  Study," *ACM SIGMETRICS*, 2010 — demonstrates that memory errors
  correlate with increased utilisation.

---

### 3. Swap Utilisation (%)

**PromQL signal:** `1 - SwapFree / SwapTotal` × 100 (guard: SwapTotal > 0)

**Why monitor it?**

Swap usage is a lagging but high-confidence indicator of memory
over-commitment.  When a system begins paging, I/O latency increases
dramatically (typical NVMe swap adds 100 µs+; HDD swap adds 10 ms+
per page fault), causing application latency spikes that are difficult
to diagnose without this signal.

On RHEL 9 cloud instances swap may not be configured; the `> 0` guard
prevents producing a constant-zero series that would confuse the framework.

**Literature:**

- B. Gregg, *Systems Performance*, 2nd ed., § 7.6 (Swap).
- Red Hat KCS article *"Understanding memory usage in RHEL"*
  <https://access.redhat.com/solutions/406773>
- W. Felter et al., "An Updated Performance Comparison of Virtual
  Machines and Linux Containers," *IEEE ISPASS*, 2015 — shows swap
  amplifies container performance variability.

---

### 4 & 5. Disk Read / Write Throughput (bytes/s)

**PromQL signals:**
- `rate(node_disk_read_bytes_total[5m])`
- `rate(node_disk_written_bytes_total[5m])`

**Device filter:** excludes `loop*` (loopback devices used by `snapd` /
container images) and `sr*` (optical drives) to reduce label cardinality.
LVM `dm-*` devices are intentionally **included** because RHEL 8/9
installs use LVM by default (`/dev/mapper/*` → `dm-0`, `dm-1`, …).

**Why monitor it?**

Disk throughput anomalies surface backup jobs gone wrong, runaway log
writers, unexpected database bulk loads, and ransomware-style mass
encryption (which produces a characteristic write-throughput surge with
high entropy data).

Read anomalies reveal cache invalidation events (e.g., after a restart)
or unusual access patterns from compromised processes.

**Literature:**

- B. Gregg, *Systems Performance*, 2nd ed., Chapter 9 (Disks) — USE
  Method applied to storage.
- Red Hat, *RHEL 8 Storage Administration Guide*,
  <https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_storage_devices/index>
- CISA Advisory AA22-321A (2022) — ransomware indicators include sudden
  disk write throughput spikes.

---

### 6. Disk I/O Utilisation (%)

**PromQL signal:** `rate(node_disk_io_time_seconds_total[5m])` × 100

**Why a separate series from throughput?**

A device can be 100 % utilised at low throughput if it is serving many
small random I/Os (e.g., a database with synchronous fsync calls).
`io_time_seconds_total` measures wall-clock time the device was busy,
making it a direct saturation indicator independent of transfer size.
Values above 100 % are possible on multi-queue NVMe devices (the kernel
reports cumulative busy time across queues) and are still useful as
relative anomaly signals.

**Literature:**

- B. Gregg, *Systems Performance*, 2nd ed., § 9.3 (Disk Utilisation).
- Linux `iostat` man page — `%util` field definition matches this metric.

---

### 7. Filesystem Usage (%)

**PromQL signal:** `1 - avail_bytes / size_bytes` × 100, filtered to
`ext[234]|xfs|btrfs|vfat`

**Why filter by filesystem type?**

RHEL 8/9 systems expose many virtual filesystems (`tmpfs`, `devtmpfs`,
`cgroup2`, `securityfs`, `selinuxfs`, `proc`, `sysfs`, …) that either
have a fixed size or are not real persistent storage.  Filtering to
physical filesystem types avoids noisy, irrelevant series.  XFS is the
RHEL 8/9 default; ext4 is common for `/boot`.

**Why monitor it?**

A full filesystem causes:
- Log rotation failure → services stop writing logs
- Database write failures → data loss or service crash
- `journald` drop → audit trail loss (compliance risk)
- Package manager failures → inability to apply security patches

Filesystem fill is typically gradual (good for the robust strategy's
MAD-based drift detection) but can be sudden (log burst, core dump).

**Literature:**

- Red Hat, *RHEL 8 System Administrator's Guide*, chapter on filesystem
  management.
- NIST SP 800-92, *Guide to Computer Security Log Management*, 2006 —
  recommends monitoring log storage capacity as a security control.

---

### 8 & 9. Network Receive / Transmit Throughput (bytes/s)

**PromQL signals:**
- `rate(node_network_receive_bytes_total[5m])`
- `rate(node_network_transmit_bytes_total[5m])`

**Interface filter:** excludes `lo`, `veth*`, `docker*`, `br-*`,
`virbr*`, `tun*`, `dummy*` to focus on host-facing physical or bond
interfaces.

**Why monitor it?**

Network throughput anomalies are among the most reliable signals for:

- **DDoS / volumetric attacks** — sudden receive spike from external
  sources
- **Data exfiltration** — unexpected transmit spike, especially
  outside business hours
- **Misbehaving application** — a service suddenly flooding the network
  (e.g., misconfigured replication, log shipping loop)
- **NIC degradation** — throughput drops to a fraction of line rate

The adaptive strategy handles the daily/weekly traffic pattern (business
hours vs. nights/weekends) automatically.

**Literature:**

- MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol) — network
  throughput monitoring is a recommended detection data source.
- B. Gregg, *Systems Performance*, 2nd ed., Chapter 10 (Network).
- C. Sridharan, "Monitoring in the Time of Cloud Native," *InfoQ*, 2017
  — RED Method (Rate, Errors, Duration) applied to infrastructure.

---

### 10. Normalised System Load (load1 / CPU count)

**PromQL signal:**
`node_load1 / count(node_cpu_seconds_total{mode="idle"}) by (instance, job)`

**Why normalise by CPU count?**

The raw `node_load1` value is not comparable across hosts of different
sizes.  A load of 4 is saturation on a 4-core VM but idle on a 32-core
bare-metal.  Dividing by the number of logical CPUs produces a
dimensionless saturation ratio where 1.0 = 100 % of compute capacity
occupied.

**Why monitor load average at all given separate CPU and I/O metrics?**

Load average is computed by the kernel as an exponentially-weighted
moving average of the number of threads in **R** (running) or **D**
(uninterruptible sleep / I/O wait) state.  It therefore captures both
CPU and I/O saturation in a single number and is sensitive to scheduler
stalls not visible in per-CPU idle time.  It is the fastest-firing
indicator before individual CPU % or iowait % rises become obvious.

**Literature:**

- B. Gregg, "Linux Load Averages: Solving the Mystery," Brendan Gregg's
  Blog, 2017 — <https://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html>
- Linux kernel `fs/proc/loadavg.c` — implementation reference.

---

### 11. Context Switch Rate (/s)

**PromQL signal:** `rate(node_context_switches_total[5m])`

**Why monitor it?**

A context switch occurs when the kernel saves the state of one thread
and restores another.  High context-switch rates indicate:

- **Lock contention** — many threads waking and sleeping on mutexes
- **Over-subscription** — more runnable threads than CPUs (soft
  saturation)
- **Noisy-neighbour effects** — on RHEL 8/9 VMs, high context-switch
  rates from other VMs on the same host can increase steal time

Normal rates vary by workload (from tens of thousands to millions per
second), making anomaly detection more useful than a fixed threshold.

**Literature:**

- B. Gregg, *BPF Performance Tools*, Chapter 6 (Scheduler) — context
  switches as a scheduler-saturation indicator.
- V. Dreizin et al., "Context Switch Overheads for Linux on ARM
  Platforms," *IEEE Embedded Systems Letters*, 2013.

---

### 12. Network Error Rate (errors/s)

**PromQL signal:**
`rate(receive_errs + transmit_errs)[5m]` summed per interface

**`anomaly_type: "errors"` rationale:**

The adaptive strategy applies a sparseness filter to `requests`-type
metrics to avoid modelling near-zero series.  Network hardware errors are
legitimately near-zero in healthy systems, so using `anomaly_type:
"errors"` bypasses the sparse filter and allows detection of even a
single sustained non-zero error rate.

**Why monitor it?**

Hardware-level network errors indicate:

- **Physical layer faults** — failing cable, SFP transceiver, or switch
  port
- **NIC firmware bugs** — driver resets causing error counter increments
- **VLAN / MTU misconfiguration** — leading to packet drops at the NIC
  layer

Network errors rarely appear in application-layer metrics (TCP retransmit
counters absorb some of them) so this node-level signal provides early
warning.

**Literature:**

- IEEE 802.3 standard — defines the frame error counters (`FCS errors`,
  `alignment errors`) that map to Linux `rx_errors` / `tx_errors`.
- Red Hat, *RHEL 8 Network Performance Tuning Guide*,
  <https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/index>

---

## RHEL 8 vs RHEL 9 compatibility notes

| Topic | RHEL 8 | RHEL 9 |
|-------|--------|--------|
| Default filesystem | XFS (LVM on) | XFS (LVM on) |
| cgroup version | v1 (unified optional) | v2 (default) |
| Swap | Present by default | May be absent on cloud images |
| NIC naming | `ens*`, `eth*`, `bond*` | Same (predictable naming) |
| node_exporter collectors | Same default set | Same default set |
| Kernel | 4.18 (RHEL 8.0) – 4.18.x | 5.14.x |

All PromQL expressions above are compatible with both RHEL 8 and RHEL 9
because they rely only on `/proc` and `/sys` interfaces that have been
stable since Linux 3.x.

## Recommended Prometheus scrape configuration

```yaml
scrape_configs:
  - job_name: node_exporter
    static_configs:
      - targets:
          - "rhel8-host-1:9100"
          - "rhel9-host-1:9100"
    # node_exporter default port is 9100
    # No extra command-line flags needed on the exporter side
```

Include this rules file in Prometheus alongside the core strategy files:

```yaml
rule_files:
  - /etc/prometheus/rules/adaptive.yml
  - /etc/prometheus/rules/robust.yml
  - /etc/prometheus/rules/examples/rhel89_node_exporter.yml
```
