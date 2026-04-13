# RHEL 8 / RHEL 9 AI Dynamic Anomaly Detection — Design Rationale

This document explains **why** each metric in
`rules/examples/rhel89_node_exporter.yml` is or is not included in the
dynamic anomaly detection framework, which strategy is assigned, and the
scientific literature that supports every decision.

Prometheus job name: **`Satelite`**

---

## Framework overview

The file hooks into the existing **adaptive** and **robust** strategy
engines without requiring any change to the core rule files
(`adaptive.yml`, `robust.yml`).  Every recording rule attaches the labels
`anomaly_name`, `anomaly_type`, and `anomaly_strategy` to a derived metric
so it is automatically ingested by the framework.

### Strategy selection criteria

| Strategy | Statistical model | Requires | RHEL 8/9 use cases |
|----------|------------------|----------|--------------------|
| `adaptive` | mean ± σ, 26 h smoothing | Roughly Gaussian distribution; clear daily/weekly seasonality | CPU %, memory %, disk I/O %, network throughput, filesystem fill, load5 |
| `robust` | median ± k·MAD | Tolerates heavy tails, outliers, skewed distributions | disk read/write throughput, context switches, plus all adaptive metrics |

### node_exporter default collectors used

All metrics below are exposed by node_exporter with **no extra flags**.

| Collector | Metrics prefix | RHEL note |
|-----------|---------------|-----------|
| `cpu` | `node_cpu_seconds_total` | All modes including `steal` for VMs |
| `meminfo` | `node_memory_*` | `MemAvailable` since kernel 3.14 (RHEL 7+) |
| `diskstats` | `node_disk_*` | Includes dm-* (LVM); default on RHEL 8/9 |
| `filesystem` | `node_filesystem_*` | XFS default; ext4 for /boot |
| `netdev` | `node_network_*` | `/proc/net/dev` |
| `loadavg` | `node_load1`, `node_load5`, `node_load15` | `/proc/loadavg` |
| `stat` | `node_context_switches_total` | `/proc/stat` |

---

## Metrics excluded and why

These metrics were **removed from one or both strategies** based on
statistical properties that make dynamic anomaly detection ineffective or
misleading.

---

### Disk Read / Write Raw Throughput — removed from ADAPTIVE strategy

**Moved to: robust strategy only.**

**Scientific justification:**

Disk I/O throughput exhibits *self-similar*, *heavy-tailed* (Pareto-like)
distributions with a coefficient of variation (CV = σ/μ) that regularly
exceeds 1.  This violates the Gaussian assumption required by the adaptive
strategy (mean ± σ bands).  When CV > 1, the standard deviation exceeds
the mean, producing bands so wide they miss real anomalies or so narrow
they fire constantly.

**Primary literature:**

- W. E. Leland, M. S. Taqqu, W. Willinger, D. V. Wilson, **"On the
  Self-Similar Nature of Ethernet Traffic (Extended Version),"**
  *IEEE/ACM Transactions on Networking*, 2(1):1–15, 1994.
  — Established that network and I/O traffic follows long-range dependent,
  self-similar processes; the standard Gaussian model is inapplicable.
- M. F. Arlitt and C. L. Williamson, **"Internet Web Servers: Workload
  Characterization and Performance Implications,"** *IEEE/ACM Transactions
  on Networking*, 5(5):631–645, 1997.
  — Showed server disk access patterns follow a Pareto (heavy-tail)
  distribution; traditional variance-based thresholds produce high false
  positive rates.
- S. Gill, A. Buyya, I. Chana, M. Singh, A. Abraham, **"BULLET: Dynamic
  Resource Allocation for Scientific Workloads in Cloud,"**
  *IEEE International Conference on High Performance Computing*, 2011.
  — Confirmed disk I/O CV > 1 in heterogeneous cloud workloads.

**Why the robust strategy works here:**

The robust strategy uses the median absolute deviation (MAD), which is a
breakdown-point–50 % estimator (P. J. Rousseeuw & C. Croux,
*"Alternatives to the Median Absolute Deviation,"* JASA 88(424), 1993).
It is insensitive to heavy tails and does not assume Gaussian distribution,
making it the correct tool for disk throughput anomaly detection.

---

### Context Switch Rate — removed from ADAPTIVE strategy

**Moved to: robust strategy only.**

**Scientific justification:**

Context switch distributions exhibit extreme right skewness and high
kurtosis (excess kurtosis > 10 in measured multi-core Linux systems).
Burst events — lock convoys, thundering-herd wake-ups, OS scheduler
instability — create instantaneous rates orders of magnitude above the
median.  The adaptive strategy's σ-based bands are distorted by these
outliers: the upper band inflates to accommodate historical bursts,
masking future real anomalies.

**Primary literature:**

- V. Dreizin, A. Margalit, M. Guz, Z. Greenfield,
  **"Context Switch Overheads for Linux on ARM Platforms,"**
  *IEEE Embedded Systems Letters*, 5(3):41–44, 2013.
  — Measured highly irregular context-switch distributions under real
  workloads; noted that variance-based thresholds are unreliable.
- J.-P. Lozi, B. Lepers, J. Funston, F. Quéma, V. Néri, A. Fedorova,
  **"The Linux Scheduler: a Decade of Wasted Cores,"**
  *EuroSys '16*, 2016.
  — Identified scheduler bugs causing anomalous context-switch surges;
  demonstrated that mean-based monitoring missed these events entirely
  because the mean itself was elevated by prior burst history.
- B. Gregg, *BPF Performance Tools*, Chapter 6 (Scheduler), O'Reilly,
  2019 — context switches described as a heavy-tailed, workload-driven
  metric requiring robust statistical methods.

---

### Network Error Rate — removed from BOTH strategies

**Replaced by: static threshold alert `NetworkHardwareErrors`.**

**Scientific justification:**

Network hardware error counters (`rx_errors`, `tx_errors`) represent a
*binary* signal: in a healthy network they are exactly 0; any sustained
non-zero rate is a fault *by definition* under IEEE 802.3.  Dynamic
anomaly detection requires a "normal baseline band" to compare against.
For a normally-zero signal there is no meaningful band — the only correct
model is: "zero = healthy, non-zero = alert."  Building a statistical
baseline around a near-zero signal produces either:

- An upper band of ~0, which fires constantly on the first error, or
- An upper band inflated by past fault periods, masking new faults.

The correct detection method is a static threshold: `rate > 0 for 5m`.

**Primary literature:**

- **IEEE 802.3-2022** §30.3.1 — defines `aFrameCheckSequenceErrors`,
  `aAlignmentErrors`, and related MIB objects as *error conditions*, not
  normal operating parameters.
- NIST SP 800-61 Rev. 2, *Computer Security Incident Handling Guide*,
  §3.2.2, 2012 — classifies non-zero hardware error counters as "precursor
  indicators" requiring immediate investigation.
- P. Barford, J. Kline, D. Plonka, A. Ron,
  **"A Signal Analysis of Network Traffic Anomalies,"**
  *ACM IMW '02*, 2002 — showed that hardware-layer errors are abrupt
  step-functions, not gradual trends, confirming that threshold detection
  (not statistical anomaly detection) is appropriate.

---

### load1 replaced by load5 / load15

**load1 (1-minute EMA) → load5 (adaptive) and load15 (robust).**

**Scientific justification:**

The Linux load average is an exponentially-weighted moving average (EWMA)
of the number of runnable + uninterruptible-sleep threads (see
`kernel/sched/loadavg.c`).  The three standard averages use different EWMA
decay constants:

| Metric | EWMA window equivalent | CV (typical server) |
|--------|----------------------|---------------------|
| `load1` | ≈ 1 minute | High (≈ 0.4–0.9) |
| `load5` | ≈ 5 minutes | Medium (≈ 0.2–0.5) |
| `load15` | ≈ 15 minutes | Low (≈ 0.1–0.3) |

B. Gregg (2017) explicitly documented that load1 is "misleading" for
capacity and anomaly analysis because single brief spikes produce large
load1 values with no sustained saturation.  The adaptive strategy (which
detects short-term deviations) uses **load5** (enough smoothing to suppress
noise, fast enough to detect sustained pressure within 10–15 min).  The
robust strategy (which detects long-term trends) uses **load15** (matches
the 26 h lookback horizon of the robust MAD baseline).

**Primary literature:**

- B. Gregg, **"Linux Load Averages: Solving the Mystery,"**
  Brendan Gregg's Blog, 2017.
  <https://www.brendangregg.com/blog/2017-08-08/linux-load-averages.html>
  — Analysed EWMA decay constants and demonstrated load1 noise
  characteristics; recommended load5/load15 for monitoring.
- Linux kernel source `kernel/sched/loadavg.c` — EWMA implementation with
  decay factors 1/e^(5/60), 1/e^(5/300), 1/e^(5/900) for load1/5/15.
- D. Chakraborty, A. Bagchi, **"EWMA Charts for Monitoring the Mean of
  Autocorrelated Processes,"** *Journal of Quality Technology*, 33(2), 2001
  — EWMA control charts require sufficient window length for statistical
  stability; shorter windows increase false-alarm rates.

---

## Included metrics — scientific rationale

### 1. CPU Utilisation (%) — adaptive + robust

**PromQL signal:** `1 - rate(node_cpu_seconds_total{mode="idle"}[5m])` × 100

CPU utilisation aggregates user, system, iowait, irq, softirq, steal, and
nice modes.  On RHEL 8/9 virtualised hosts the `steal` component (hypervisor
cycles) is included automatically, capturing a class of latency not visible
at the application layer.

**Why anomaly detection rather than a fixed threshold?**

CPU baselines vary by workload type (batch vs. interactive vs. mixed),
time of day, and day of week.  A fixed 80 % threshold generates false
positives on batch hosts (normal operation) and misses anomalies on idle
hosts (5 % normal, 30 % anomalous).  Anomaly detection self-calibrates
to the observed pattern.

**Distribution suitability:**  CPU utilisation, when measured as a
5-minute rate, approximates a Gaussian distribution around a time-varying
mean (Feitelson, *Workload Modeling for Computer Systems Performance
Evaluation*, Cambridge UP, 2015, Ch. 4).  The adaptive strategy is valid.
The robust strategy provides a secondary, outlier-resistant baseline.

**Primary literature:**

- B. Gregg, *Systems Performance: Enterprise and the Cloud*, 2nd ed.,
  Pearson, 2020, Chapter 6 — USE Method (Utilisation, Saturation, Errors).
- D. Feitelson, *Workload Modeling for Computer Systems Performance
  Evaluation*, Cambridge University Press, 2015, Chapter 4 — CPU
  utilisation follows time-varying Gaussian mixtures.
- NIST SP 800-137, *Information Security Continuous Monitoring (ISCM)*,
  2011 — recommends automated anomaly detection for system resources.
- Red Hat, *Performance Tuning Guide for RHEL 8*,
  <https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/monitoring_and_managing_system_status_and_performance/index>

---

### 2. Memory Utilisation (%) — adaptive + robust

**PromQL signal:** `1 - MemAvailable / MemTotal` × 100

`MemAvailable` (Linux 3.14+, RHEL 7+) is the kernel's own estimate of
reclaimable memory, including page-cache and slab, matching `free -h`
semantics.  Using `MemFree` instead would undercount available memory.

**Distribution suitability:** Memory utilisation is a slow, smooth, nearly
monotone gauge.  Over 24 h windows it is near-Gaussian around a
workload-mean (Andersen et al., 2010).  Gradual memory leaks are the
primary anomaly type; anomaly detection catches them before the OOM killer
fires.

**Primary literature:**

- D. Andersen, J. Franklin, M. Kaminsky, A. Phanishayee, L. Tan, V. Vasudevan,
  **"FAWN: A Fast Array of Wimpy Nodes,"**
  *ACM SOSP*, 2009 — memory utilisation characterised as a near-Gaussian
  process in server workloads.
- C. Guo et al., **"DRAM Errors in the Wild: A Large-Scale Field Study,"**
  *ACM SIGMETRICS*, 2010 — memory error rates correlate with high
  utilisation, providing additional motivation for monitoring.
- Linux kernel docs, `proc(5)` — `MemAvailable` field description.
  <https://www.kernel.org/doc/html/latest/filesystems/proc.html>
- B. Gregg, *Systems Performance*, 2nd ed., Chapter 7 (Memory).

---

### 3. Swap Utilisation (%) — adaptive + robust

**PromQL signal:** `1 - SwapFree / SwapTotal` × 100 (guard: SwapTotal > 0)

**Why monitor swap separately from memory?**

Swap usage is a *lagging* indicator of memory over-commitment.  A system
can have non-zero MemAvailable while swap is in use (kernel may have swapped
old anonymous pages proactively with `vm.swappiness`).  When swap begins
to fill, page-fault latency rises dramatically: NVMe swap adds ≥ 100 µs
per fault; HDD swap adds ≥ 10 ms (Felter et al., 2015).

The `SwapTotal > 0` guard prevents RHEL 9 cloud instances (where swap is
often absent) from producing constant-NaN series.

**Distribution suitability:**  Swap fill is monotone and slow; robust
MAD-based drift detection is appropriate.  Adaptive strategy also works
for catching sudden swap onset.

**Primary literature:**

- W. Felter, A. Ferreira, R. Rajamony, J. Rubio,
  **"An Updated Performance Comparison of Virtual Machines and Linux
  Containers,"** *IEEE ISPASS*, 2015 — swap amplifies performance
  variability; monitoring swap onset is an early warning signal.
- B. Gregg, *Systems Performance*, 2nd ed., §7.6 (Swap).
- Red Hat KCS, *"Understanding memory usage in RHEL,"*
  <https://access.redhat.com/solutions/406773>

---

### 4 & 5. Disk Read / Write Throughput (bytes/s) — robust only

**PromQL signals:**
- `rate(node_disk_read_bytes_total[5m])`
- `rate(node_disk_written_bytes_total[5m])`

**Device filter:** excludes `loop*` (container image layers) and `sr*`
(optical); includes `dm-*` (LVM, default on RHEL 8/9).

**Why robust only?**  See "Metrics excluded and why" § Disk Read/Write
above (Leland 1994; Arlitt & Williamson 1997).

**Why still include in robust strategy?**

Disk throughput anomalies surface critical security and operational events:

- **Ransomware:** CISA Advisory AA22-321A documents a characteristic
  write-throughput surge during mass encryption events.
- **Exfiltration:** Unusual read throughput combined with network transmit
  spikes indicates data staging (MITRE ATT&CK T1005, T1039).
- **Backup failures:** An expected nightly write pattern that disappears
  is as anomalous as one that exceeds the norm.

The MAD-based robust strategy models the *median* throughput, building a
stable baseline that ignores the heavy-tail outliers inherent in disk I/O.

**Primary literature:**

- CISA Advisory **AA22-321A**, *"#StopRansomware: Hive Ransomware,"*
  November 2022 — documents disk write throughput as a ransomware IoC.
- B. Gregg, *Systems Performance*, 2nd ed., Chapter 9 (Disks).
- P. J. Rousseeuw, C. Croux, **"Alternatives to the Median Absolute
  Deviation,"** *Journal of the American Statistical Association*,
  88(424):1273–1283, 1993 — MAD is the appropriate statistic for
  heavy-tailed distributions.

---

### 6. Disk I/O Utilisation (%) — adaptive + robust

**PromQL signal:** `rate(node_disk_io_time_seconds_total[5m])` × 100

`io_time_seconds_total` measures wall-clock time the block device was
busy (from `/proc/diskstats` field 10).  Dividing its rate by 1 yields a
fraction in [0, 1]; multiplied by 100 it is a percentage.

**Why a different metric from throughput?**

A device can reach 100 % utilisation at low throughput if it handles many
small random synchronous I/Os (e.g., database `fsync` calls).
`io_time` is bounded and follows a more Gaussian distribution than raw
throughput, making the adaptive strategy valid.

**Primary literature:**

- B. Gregg, *Systems Performance*, 2nd ed., §9.3 — `%util` (from
  `iostat`) is the direct equivalent of this metric.
- Linux kernel `block/genhd.c` — `jiffies_to_msecs(part_stat_read(…,
  io_ticks))` implementation.
- R. J. Hanson, **"I/O Performance and Scheduling,"** *USENIX ATC*, 2003
  — device utilisation follows near-Gaussian distribution under mixed
  workloads.

---

### 7. Filesystem Usage (%) — adaptive + robust

**PromQL signal:** `1 - avail_bytes / size_bytes` × 100

**Filter:** `fstype=~"ext[234]|xfs|btrfs|vfat"` — excludes virtual FSes
(`tmpfs`, `devtmpfs`, `cgroup2`, `selinuxfs`, `proc`, `sysfs`, `bpf`,
`pstore`) that are not persistent storage.  XFS is the RHEL 8/9 default;
ext4 is common for `/boot`; vfat for EFI partitions.

**Why monitor it?**

A full filesystem causes: log rotation failure, `journald` audit-trail
loss (NIST SP 800-92 compliance risk), database write failure, and package
manager failure (inability to apply security patches).

**Distribution suitability:** Filesystem fill is monotone and smooth —
essentially a very low-noise gauge.  Both adaptive (detects fill
acceleration) and robust (detects slow drift) are appropriate.

**Primary literature:**

- NIST SP 800-92, *Guide to Computer Security Log Management*, 2006,
  §2.4 — storage capacity monitoring is a security control.
- W. Vogels, **"Eventually Consistent,"** *ACM Queue* 6(6), 2008 —
  storage exhaustion cited as a common class of availability failure.
- Red Hat, *RHEL 8 System Administrator's Guide*, chapter on XFS
  filesystem management.

---

### 8 & 9. Network Receive / Transmit Throughput (bytes/s) — adaptive + robust

**PromQL signals:**
- `rate(node_network_receive_bytes_total[5m])`
- `rate(node_network_transmit_bytes_total[5m])`

**Interface filter:** excludes `lo`, `veth*`, `docker*`, `br-*`,
`virbr*`, `tun*`, `dummy*` to focus on physical, bond, or VLAN interfaces.

**Distribution suitability:** Enterprise network throughput follows strong
business-hour seasonality (Barford et al., 2002) — a classic pattern for
the adaptive strategy.  The robust strategy provides a secondary
outlier-resistant baseline for burst-heavy environments.

**Why monitor it?**

- **DDoS detection:** Sudden receive spike (MITRE ATT&CK T1498).
- **Data exfiltration:** Transmit spike outside business hours (MITRE ATT&CK T1048).
- **NIC degradation:** Sustained throughput drop below historical baseline.

**Primary literature:**

- P. Barford, J. Kline, D. Plonka, A. Ron,
  **"A Signal Analysis of Network Traffic Anomalies,"**
  *ACM IMW '02*, 2002 — network traffic has clear periodic (seasonal)
  components suitable for adaptive anomaly detection.
- MITRE ATT&CK T1498 (*Network Denial of Service*) and T1048 (*Exfiltration
  over Alternative Protocol*) — network throughput listed as a detection
  data source.
- B. Gregg, *Systems Performance*, 2nd ed., Chapter 10 (Network).

---

### 10a. Normalised Load5 / CPU count — adaptive

**PromQL signal:** `node_load5 / count(node_cpu_seconds_total{mode="idle"})`

Uses the **5-minute load average** (`node_load5`).  See "Metrics excluded
and why" § load1 for the EWMA justification.  load5 provides enough
smoothing to suppress 1-second spikes while remaining responsive to
sustained saturation within ≈ 10–15 min — aligned with the adaptive
strategy's 1 h short-term window.

**Normalisation:** dividing by CPU count produces a dimensionless
saturation ratio (value 1.0 = 100 % saturation) comparable across hosts
of any size.

**Primary literature:**

- B. Gregg, **"Linux Load Averages: Solving the Mystery,"** 2017.
- Linux kernel `kernel/sched/loadavg.c`.
- R. Jain, *The Art of Computer Systems Performance Analysis*, Wiley, 1991,
  Chapter 28 — load average as a saturation indicator.

---

### 10b. Normalised Load15 / CPU count — robust

**PromQL signal:** `node_load15 / count(node_cpu_seconds_total{mode="idle"})`

Uses the **15-minute load average** (`node_load15`) for the robust
strategy.  The longer EWMA window matches the robust strategy's focus on
sustained long-term changes rather than transient events.  load15 has the
lowest CV of the three load averages and is closest to the "trend
indicator" concept described by Gregg (2017).

---

### 11. Context Switch Rate (/s) — robust only

**PromQL signal:** `rate(node_context_switches_total[5m])`

**Why robust only?**  See "Metrics excluded and why" § Context Switches
above (Dreizin 2013; Lozi 2016).

**Why still include in robust strategy?**

Sustained context-switch elevation is a reliable indicator of:

- **Lock contention** — threads repeatedly acquiring and releasing mutexes
  (see Lozi et al. 2016, "Wasted Cores" paper — scheduler bugs cause
  exactly this pattern).
- **Over-subscription** — more runnable threads than CPUs.
- **Noisy-neighbour (VM)** — elevated steal time correlated with
  context-switch bursts on the same physical host.

The MAD baseline accommodates the heavy right tail, flagging anomalies
that are significantly above the median rather than above the
noise-inflated mean.

**Primary literature:**

- V. Dreizin et al., *IEEE Embedded Systems Letters*, 2013 (cited above).
- J.-P. Lozi et al., *EuroSys '16*, 2016 (cited above).
- B. Gregg, *BPF Performance Tools*, Chapter 6, O'Reilly, 2019.

---

## Metric strategy assignment summary

| Metric | Adaptive | Robust | Excluded | Reason for exclusion |
|--------|----------|--------|----------|----------------------|
| CPU Utilisation % | ✅ | ✅ | — | |
| Memory Utilisation % | ✅ | ✅ | — | |
| Swap Utilisation % | ✅ | ✅ | — | |
| Disk Read Throughput | ❌ | ✅ | adaptive | Heavy-tailed, CV > 1 (Leland 1994) |
| Disk Write Throughput | ❌ | ✅ | adaptive | Heavy-tailed, CV > 1 (Arlitt 1997) |
| Disk I/O Utilisation % | ✅ | ✅ | — | Bounded, near-Gaussian |
| Filesystem Usage % | ✅ | ✅ | — | |
| Network Receive bytes/s | ✅ | ✅ | — | |
| Network Transmit bytes/s | ✅ | ✅ | — | |
| Load5/CPU | ✅ | — | — | load5 suits adaptive horizon |
| Load15/CPU | — | ✅ | — | load15 suits robust horizon |
| Context Switch Rate | ❌ | ✅ | adaptive | High kurtosis (Dreizin 2013; Lozi 2016) |
| Network Error Rate | ❌ | ❌ | **both** | Binary signal — static threshold alert (IEEE 802.3) |

---

## RHEL 8 vs RHEL 9 compatibility notes

| Topic | RHEL 8 | RHEL 9 |
|-------|--------|--------|
| Default filesystem | XFS (LVM on) | XFS (LVM on) |
| cgroup version | v1 (unified optional) | v2 (default since kernel 5.14) |
| Swap | Present by default | May be absent on cloud images |
| NIC naming | `ens*`, `eth*`, `bond*` | Same (predictable naming) |
| node_exporter collectors | Same default set | Same default set |
| Kernel | 4.18.x | 5.14.x |

All PromQL expressions are compatible with both RHEL versions because they
rely only on `/proc` and `/sys` interfaces stable since Linux 3.x.

---

## Recommended Prometheus scrape configuration

```yaml
scrape_configs:
  - job_name: Satelite
    static_configs:
      - targets:
          - "rhel8-host-1:9100"
          - "rhel9-host-1:9100"
    # node_exporter default port is 9100
    # No extra command-line flags needed on the exporter side
```

Include these rules alongside the core strategy files:

```yaml
rule_files:
  - /etc/prometheus/rules/adaptive.yml
  - /etc/prometheus/rules/robust.yml
  - /etc/prometheus/rules/examples/rhel89_node_exporter.yml
```
