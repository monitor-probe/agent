//! Linux-only metric collection, read directly from /proc and statvfs.
//! sysinfo is not used: it misreports memory and disk for this purpose.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Instant;

use serde::Serialize;

/// Interfaces that carry neither this machine's traffic nor its identity:
/// loopback, container and VM networks, and tunnels whose bytes reach the wire
/// a second time inside their carrier.
///
/// `tailscale` belongs to the tunnel group for the same reason `wg` does: it is
/// WireGuard under another name, on an interface not called `wg0`.
///
/// ponytail: a name list, so the next tunnel will be missed as well. The kernel
/// knows the answer -- a real NIC has /sys/class/net/<name>/device, a virtual
/// one does not -- but a card wrongly failing that test loses a node's entire
/// traffic, where a missing name only doubles it. Worth the swap only after
/// verification against every card in the fleet.
const SKIP_IFACES: &[&str] = &[
    "lo",
    "docker",
    "veth",
    "br-",
    "virbr",
    "tap",
    "tun",
    "wg",
    "tailscale",
    "cni",
    "flannel",
    "podman",
    "fwbr",
    "fwpr",
    "kube",
    "cali",
    "nerdctl",
    "zt",
];

/// Pseudo/virtual filesystems that must not count toward disk totals.
const SKIP_FSTYPES: &[&str] = &[
    "tmpfs",
    "devtmpfs",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "mqueue",
    "hugetlbfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "binfmt_misc",
    "autofs",
    "squashfs",
    "ramfs",
    "efivarfs",
    "nsfs",
    "overlay",
    "fuse",
    "rpc_pipefs",
    // Remote storage. `//server/share` passes the device check that excludes
    // `server:/export`, so only the type list keeps a NAS out of this machine's
    // capacity. Each spelling needs its own entry: the flavour rule below
    // matches on a dot, so "nfs" does not cover "nfs4".
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "ceph",
    "glusterfs",
    "9p",
];

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub virt: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub mem_total: u64,
    pub swap_total: u64,
    pub disk_total: u64,
    pub agent_version: String,
    /// The host's own addresses, public ones first; see [`pick`]. The hub sees
    /// only the family the agent connected over.
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    /// Identifies this boot. It changes on reboot, which is how the hub knows
    /// the kernel's byte counters restarted at zero.
    pub boot_id: String,
    pub uptime: u64,
    pub cpu: f32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    /// Kernel lifetime byte counters. The hub accumulates these; the agent
    /// stores nothing and does not attempt to survive a reboot.
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp: u32,
    pub udp: u32,
    pub procs: u32,
}

#[derive(Default)]
pub struct Collector {
    prev_cpu: Option<(u64, u64)>,
    prev_net: Option<(Instant, u64, u64)>,
}

impl Collector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn facts(&self) -> Facts {
        let (v4, v6) = addresses();
        let mem = meminfo();
        let (cpu_name, cpu_cores) = cpuinfo();
        let (disk_total, _) = disk_usage(&real_mount_points());
        Facts {
            hostname: read_trim("/proc/sys/kernel/hostname").unwrap_or_else(|| "unknown".into()),
            os: os_pretty_name(),
            kernel: read_trim("/proc/sys/kernel/osrelease").unwrap_or_else(|| "unknown".into()),
            arch: std::env::consts::ARCH.into(),
            virt: virtualization(),
            cpu_name,
            cpu_cores,
            mem_total: mem.get("MemTotal").copied().unwrap_or(0),
            swap_total: mem.get("SwapTotal").copied().unwrap_or(0),
            disk_total,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ipv4: v4,
            ipv6: v6,
        }
    }

    pub fn collect(&mut self) -> Metrics {
        let mem = meminfo();
        let (mem_total, mem_used) = mem_used(&mem);
        let (swap_total, swap_used) = swap_used(&mem);
        let (disk_total, disk_used) = disk_usage(&real_mount_points());
        let (rx_total, tx_total) = net_totals();
        let (rx, tx) = self.net_rate(rx_total, tx_total, Instant::now());
        let (tcp, udp) = conn_counts();

        Metrics {
            boot_id: read_trim("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
            uptime: uptime(),
            cpu: self.cpu_percent(),
            load: loadavg(),
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            disk_total,
            disk_used,
            net_rx_total: rx_total,
            net_tx_total: tx_total,
            net_rx: rx,
            net_tx: tx,
            tcp,
            udp,
            procs: proc_count(),
        }
    }

    /// CPU busy share since the previous call. The first call has no baseline
    /// and reports 0 rather than a since-boot average.
    fn cpu_percent(&mut self) -> f32 {
        let Some(now) = cpu_jiffies() else {
            return 0.0;
        };
        let pct = self.prev_cpu.map_or(0.0, |prev| busy_percent(prev, now));
        self.prev_cpu = Some(now);
        pct
    }

    fn net_rate(&mut self, rx: u64, tx: u64, now: Instant) -> (u64, u64) {
        let rate = match self.prev_net {
            Some((t, prx, ptx)) => {
                let secs = now.saturating_duration_since(t).as_secs_f64();
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    // A counter that moved backwards means a reboot or a wrap:
                    // report no rate rather than a spurious spike.
                    (
                        (rx.saturating_sub(prx) as f64 / secs) as u64,
                        (tx.saturating_sub(ptx) as f64 / secs) as u64,
                    )
                }
            }
            None => (0, 0),
        };
        self.prev_net = Some((now, rx, tx));
        rate
    }
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
}

/// Parses /proc/meminfo into bytes keyed by field name.
fn meminfo() -> HashMap<String, u64> {
    parse_meminfo(&fs::read_to_string("/proc/meminfo").unwrap_or_default())
}

fn parse_meminfo(text: &str) -> HashMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let (key, rest) = line.split_once(':')?;
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            Some((key.to_owned(), kb * 1024))
        })
        .collect()
}

/// `free(1)`'s used column: total minus the kernel's MemAvailable estimate.
/// sysinfo's `used_memory()` counts page cache as used and reads gigabytes high
/// on a host that has been up for a while.
fn mem_used(m: &HashMap<String, u64>) -> (u64, u64) {
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    let total = g("MemTotal");
    if total == 0 {
        return (0, 0);
    }
    // Absence selects the fallback, not a zero value: a host under real memory
    // pressure reports MemAvailable 0, and treating that as a missing field
    // would understate used memory precisely when it matters.
    let available =
        m.get("MemAvailable").copied().unwrap_or_else(|| g("MemFree") + g("Buffers") + g("Cached"));
    (total, total.saturating_sub(available))
}

/// `free(1)`'s Swap used column: `SwapTotal - SwapFree`, nothing more.
///
/// Subtracting `SwapCached` would imply that pages swapped back in had released
/// their slots. They have not -- the copy on the device still occupies blocks
/// until something else claims them -- and the result runs about a fifth low.
fn swap_used(m: &HashMap<String, u64>) -> (u64, u64) {
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    let total = g("SwapTotal");
    (total, total.saturating_sub(g("SwapFree")))
}

/// Busy share between two `(total, idle)` jiffy readings.
///
/// Split out of [`Collector::cpu_percent`] so the arithmetic can be asserted
/// directly rather than only against a live machine.
fn busy_percent(prev: (u64, u64), now: (u64, u64)) -> f32 {
    let ((pt, pi), (total, idle)) = (prev, now);
    if total <= pt {
        return 0.0;
    }
    let dt = (total - pt) as f32;
    let di = idle.saturating_sub(pi) as f32;
    ((dt - di) / dt * 100.0).clamp(0.0, 100.0)
}

fn cpu_jiffies() -> Option<(u64, u64)> {
    parse_cpu_jiffies(&fs::read_to_string("/proc/stat").ok()?)
}

fn parse_cpu_jiffies(text: &str) -> Option<(u64, u64)> {
    let line = text.lines().next()?.strip_prefix("cpu ")?;
    let v: Vec<u64> = line.split_whitespace().filter_map(|f| f.parse().ok()).collect();
    if v.len() < 5 {
        return None;
    }
    // idle and iowait are both time the CPU did no work. guest and guest_nice
    // are already included in user and nice, so the sum stops before them
    // rather than counting that time twice.
    Some((v.iter().take(8).sum(), v[3] + v[4]))
}

fn loadavg() -> [f32; 3] {
    let text = fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let mut it = text.split_whitespace();
    let mut next = || it.next().and_then(|v| v.parse().ok()).unwrap_or(0.0);
    [next(), next(), next()]
}

fn uptime() -> u64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|t| t.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or(0.0) as u64
}

/// One address of each family the machine holds. Behind NAT the v4 is private,
/// which is what the machine actually holds -- no external service is
/// consulted.
///
/// Filtered by [`SKIP_IFACES`] alone, so a docker bridge cannot pass for the
/// machine's address. [`is_stacked`] is not applied here: it answers whether
/// bytes were already counted lower down, and a bridge holding the host address
/// is both stacked and this machine.
fn addresses() -> (String, String) {
    let transient = transient_v6(&fs::read_to_string("/proc/net/if_inet6").unwrap_or_default());
    let held: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !skip_iface(&i.name) && !i.is_link_local() && i.is_oper_up())
        .map(|i| i.ip())
        .collect();
    pick(&held, &transient)
}

/// A public address before any other, then a stable v6 before a transient
/// one; ties keep the kernel's order. Taking the first address instead would
/// report a ULA or a proxy's TUN address whenever its interface is listed
/// ahead of the one holding the public address: an LXC guest with a ULA on
/// eth0 and its public /128 on eth1 would report the ULA.
fn pick(held: &[IpAddr], transient: &[Ipv6Addr]) -> (String, String) {
    let best = |v6: bool| {
        held.iter()
            .filter(|ip| ip.is_ipv6() == v6)
            .min_by_key(|ip| (!is_public(**ip), matches!(ip, IpAddr::V6(a) if transient.contains(a))))
            .map_or_else(String::new, ToString::to_string)
    };
    (best(false), best(true))
}

/// IPv6 addresses held but not worth reporting: temporary (privacy extensions,
/// replaced daily), deprecated (past their preferred lifetime, as an old
/// prefix is after a home line redials), tentative, or failed duplicate
/// detection. Read from /proc/net/if_inet6, whose fields are address, ifindex,
/// prefix length, scope, flags and name; if_addrs does not expose the flags.
fn transient_v6(text: &str) -> Vec<Ipv6Addr> {
    // IFA_F_TEMPORARY | IFA_F_DADFAILED | IFA_F_DEPRECATED | IFA_F_TENTATIVE
    const TRANSIENT: u8 = 0x01 | 0x08 | 0x20 | 0x40;
    text.lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            let addr = u128::from_str_radix(f.next()?, 16).ok()?;
            let flags = u8::from_str_radix(f.nth(3)?, 16).ok()?;
            (flags & TRANSIENT != 0).then(|| Ipv6Addr::from(addr))
        })
        .collect()
}

/// Globally routable. Excluded on the v4 side: RFC 1918, CGNAT (100.64/10),
/// loopback, link-local, 0/8, 192.0.0/24 (where 464XLAT places its CLAT),
/// 198.18/15 (the fake-IP range TUN-mode proxies such as Clash assign to
/// themselves), multicast and reserved. On the v6 side only 2000::/3 counts,
/// which leaves out ULA (fc00::/7), link-local and loopback.
///
/// The hub and its panel apply the same ranges to the addresses this agent
/// reports; the three lists are to be changed together.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000,
    }
}

/// Sums the kernel's lifetime byte counters, one count per byte on the wire.
fn net_totals() -> (u64, u64) {
    parse_net_dev(&fs::read_to_string("/proc/net/dev").unwrap_or_default())
}

fn parse_net_dev(text: &str) -> (u64, u64) {
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if skip_iface(name) || is_stacked(name) {
            continue;
        }
        let f: Vec<u64> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
        if f.len() >= 9 {
            rx = rx.saturating_add(f[0]);
            tx = tx.saturating_add(f[8]);
        }
    }
    (rx, tx)
}

fn skip_iface(name: &str) -> bool {
    SKIP_IFACES.iter().any(|p| name.starts_with(p))
}

/// Stacked on top of another interface: bonds, bridges, VLAN children. The
/// kernel books one packet on both, so counting these would double the traffic
/// the hub bills.
///
/// A traffic rule only. These interfaces are where a host's own address most
/// often sits -- `vmbr0` on Proxmox, `bond0` where two ports form one link --
/// and whether bytes were already counted says nothing about address
/// ownership.
fn is_stacked(name: &str) -> bool {
    name.contains('.') || ["bond", "br", "vlan", "vmbr"].iter().any(|p| name.starts_with(p))
}

/// A pseudo filesystem, named outright or as a flavour of one such as
/// `fuse.lxcfs`. Matched against the field rather than by building `"{s}."` per
/// candidate, which would allocate a few hundred strings per second.
fn skip_fstype(fstype: &str) -> bool {
    SKIP_FSTYPES.iter().any(|s| fstype == *s || fstype.strip_prefix(s).is_some_and(|r| r.starts_with('.')))
}

/// Mount points backed by real storage, deduplicated by source device so a bind
/// mount or a second subvolume cannot double-count the same disk.
///
/// Re-read every sample rather than cached at startup, otherwise a disk attached
/// later stays invisible until the agent restarts. /proc/self/mounts is a few
/// kilobytes.
fn real_mount_points() -> Vec<String> {
    parse_mounts(&fs::read_to_string("/proc/self/mounts").unwrap_or_default())
}

fn mount_rows(text: &str) -> Vec<(&str, &str, &str)> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            (f.len() >= 3).then(|| (f[0], f[1], f[2]))
        })
        .collect()
}

fn parse_mounts(text: &str) -> Vec<String> {
    let mut seen = Vec::new();
    let mut out = Vec::new();
    let rows = mount_rows(text);
    for (i, &(dev, mount, fstype)) in rows.iter().enumerate() {
        // The table is in mount order and a path resolves to the last mount on
        // it, which is what statvfs below answers for. An earlier entry for the
        // same point remains listed but is no longer reachable: under
        // ProtectHome=yes a host whose /home is its own filesystem has that row
        // sitting beneath a tmpfs, and counting it would book the tmpfs's size
        // as /home's.
        if rows[i + 1..].iter().any(|(_, m, _)| *m == mount) {
            continue;
        }
        if skip_fstype(fstype) {
            continue;
        }
        if !dev.starts_with('/') && fstype != "zfs" && fstype != "btrfs" {
            continue;
        }
        // ZFS datasets and btrfs subvolumes share one pool's free space.
        let key = dev.split('/').next().filter(|_| fstype == "zfs").unwrap_or(dev).to_owned();
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(mount.replace("\\040", " "));
    }
    out
}

/// Mount points where a real filesystem sits beneath one this agent does not
/// count, so `statvfs` answers for the layer on top and the one below is absent
/// from the totals.
///
/// The `install.sh` unit sets `ProtectHome=yes`, which mounts a tmpfs over
/// /home. Where /home is its own filesystem, `df` on the host and the panel then
/// disagree by its entire size. Reported once at startup, since the discrepancy
/// is otherwise visible only in the totals themselves.
pub fn shadowed_mounts(text: &str) -> Vec<String> {
    let rows = mount_rows(text);
    rows.iter()
        .enumerate()
        .filter(|(i, (dev, mount, fstype))| {
            dev.starts_with('/')
                && !skip_fstype(fstype)
                && rows[i + 1..]
                    .iter()
                    .find(|(_, m, _)| m == mount)
                    .is_some_and(|(_, _, top)| skip_fstype(top))
        })
        .map(|(_, (_, mount, _))| mount.replace("\\040", " "))
        .collect()
}

/// `used = total - free`, exactly what df reports. `total - available` would
/// charge ext4's 5% root reserve to the user and show a fresh disk several
/// percent full.
///
/// Blocking, on the thread that also runs the reporting loop. [`SKIP_FSTYPES`]
/// is what makes that safe: the mounts that hang in D state until a server
/// answers -- nfs, cifs, ceph, fuse -- never reach this call. Removing an entry
/// from that list would let a dead NAS freeze the agent, watchdog included.
fn disk_usage(mounts: &[String]) -> (u64, u64) {
    let mut total = 0u64;
    let mut used = 0u64;
    for m in mounts {
        let Ok(s) = rustix::fs::statvfs(m.as_str()) else { continue };
        let bs = if s.f_frsize > 0 { s.f_frsize } else { s.f_bsize };
        total = total.saturating_add(s.f_blocks.saturating_mul(bs));
        used = used.saturating_add(s.f_blocks.saturating_sub(s.f_bfree).saturating_mul(bs));
    }
    (total, used)
}

/// Socket counts from /proc/net/sockstat, a handful of short lines. Counting
/// lines in /proc/net/tcp would read the whole connection table once a second --
/// hundreds of kilobytes on a busy host, for a number the kernel already keeps.
/// TIME_WAIT sockets live in the v4 `tw` counter for both families, so they are
/// added once.
fn conn_counts() -> (u32, u32) {
    parse_sockstat(
        &fs::read_to_string("/proc/net/sockstat").unwrap_or_default(),
        &fs::read_to_string("/proc/net/sockstat6").unwrap_or_default(),
    )
}

fn parse_sockstat(v4: &str, v6: &str) -> (u32, u32) {
    let stat = |text: &str, prefix: &str, key: &str| {
        text.lines()
            .find_map(|line| {
                let mut fields = line.strip_prefix(prefix)?.split_whitespace();
                while let Some(word) = fields.next() {
                    if word == key {
                        return fields.next()?.parse::<u32>().ok();
                    }
                }
                None
            })
            .unwrap_or(0)
    };
    (
        stat(v4, "TCP:", "inuse") + stat(v4, "TCP:", "tw") + stat(v6, "TCP6:", "inuse"),
        stat(v4, "UDP:", "inuse") + stat(v6, "UDP6:", "inuse"),
    )
}

fn proc_count() -> u32 {
    fs::read_dir("/proc")
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().bytes().all(|b| b.is_ascii_digit()))
                .count() as u32
        })
        .unwrap_or(0)
}

fn cpuinfo() -> (String, u32) {
    let text = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let name = text
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            matches!(k.trim(), "model name" | "Model" | "cpu model").then(|| v.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown".into());
    let cores = text.lines().filter(|l| l.starts_with("processor")).count().max(1) as u32;
    (name, cores)
}

fn os_pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|t| {
            t.lines().find_map(|l| Some(l.strip_prefix("PRETTY_NAME=")?.trim_matches('"').to_owned()))
        })
        .unwrap_or_else(|| "Linux".into())
}

fn virtualization() -> String {
    if fs::metadata("/proc/vz").is_ok() {
        return "openvz".into();
    }
    if fs::metadata("/proc/xen").is_ok() {
        return "xen".into();
    }
    if fs::metadata("/.dockerenv").is_ok() {
        return "docker".into();
    }
    if let Some(t) = read_trim("/sys/hypervisor/type") {
        return t.to_lowercase();
    }
    for path in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"] {
        let Some(v) = read_trim(path) else { continue };
        let l = v.to_lowercase();
        for k in ["kvm", "vmware", "virtualbox", "qemu", "hyper-v", "xen", "bochs", "amazon", "google"] {
            if l.contains(k) {
                return k.into();
            }
        }
    }
    if fs::read_to_string("/proc/cpuinfo").is_ok_and(|t| t.contains("hypervisor")) {
        "vm".into()
    } else {
        "none".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_matches_free_not_sysinfo() {
        // Real /proc/meminfo from a 3.8 GiB host holding 2.5 GiB of cache.
        let m = parse_meminfo(
            "MemTotal:        4008884 kB\nMemFree:          602756 kB\nMemAvailable:    2947484 kB\n\
             Buffers:          129100 kB\nCached:          2351560 kB\nSReclaimable:     154008 kB\n\
             Shmem:              2176 kB\nSwapTotal:       1048572 kB\nSwapFree:         987264 kB\n\
             SwapCached:        13280 kB\n",
        );
        let (total, used) = mem_used(&m);
        assert_eq!(total, 4008884 * 1024);
        assert_eq!(used, (4008884 - 2947484) * 1024, "must match the `free` used column");
        // Counting cache as used would report ~3.3 GiB here.
        assert!(used < (total - g_cached(&m)), "page cache must not count as used");

        // free's Swap used column is total - free. SwapCached is not
        // subtracted: those pages still occupy their blocks on the device.
        let (st, su) = swap_used(&m);
        assert_eq!(st, 1048572 * 1024);
        assert_eq!(su, (1048572 - 987264) * 1024, "must match the `free` swap used column");
    }

    fn g_cached(m: &HashMap<String, u64>) -> u64 {
        m.get("Cached").copied().unwrap_or(0)
    }

    #[test]
    fn memory_falls_back_when_memavailable_is_absent() {
        let m = parse_meminfo("MemTotal: 1000 kB\nMemFree: 200 kB\nBuffers: 100 kB\nCached: 300 kB\n");
        assert_eq!(mem_used(&m), (1000 * 1024, 400 * 1024));
        assert_eq!(mem_used(&HashMap::new()), (0, 0));
    }

    #[test]
    fn cpu_percent_needs_a_baseline_then_uses_deltas() {
        assert_eq!(parse_cpu_jiffies("cpu  40 0 35 925 0 0 0 0 0 0\n"), Some((1000, 925)));
        // The last two columns are guest and guest_nice, already counted in
        // user and nice: 80 busy jiffies, not 1080.
        assert_eq!(parse_cpu_jiffies("cpu  10 10 10 10 10 10 10 10 500 500\n"), Some((80, 20)));
        assert!(parse_cpu_jiffies("garbage").is_none());

        // 100 more jiffies since the baseline, 25 idle => 75% busy. Asserted
        // against the function the binary runs rather than a copy of the
        // formula, which would not catch busy and idle being swapped.
        assert_eq!(busy_percent((1000, 925), (1100, 950)), 75.0);
        assert_eq!(busy_percent((1000, 925), (1100, 1025)), 0.0, "a fully idle interval is 0% busy");
        // A counter that moved backwards indicates a reboot, not 100% busy.
        assert_eq!(busy_percent((1000, 925), (500, 400)), 0.0);
        // The first call has no baseline, so it reports 0.
        assert_eq!(Collector::new().cpu_percent(), 0.0);
    }

    #[test]
    fn socket_counts_come_from_sockstat_not_the_connection_table() {
        let v4 = "sockets: used 226\nTCP: inuse 78 orphan 1 tw 7 alloc 85 mem 119\nUDP: inuse 2 mem 150\n";
        let v6 = "TCP6: inuse 1\nUDP6: inuse 4\n";
        // Matches counting lines in /proc/net/tcp{,6}: TIME_WAIT sockets are
        // held in the v4 `tw` field for both families.
        assert_eq!(parse_sockstat(v4, v6), (86, 6));
        assert_eq!(parse_sockstat("", ""), (0, 0));
    }

    /// One byte on the wire, counted once. Every line but eth0 is that same
    /// byte booked a second time: bond, bridge and VLAN are stacked over it,
    /// and a tunnel's payload leaves inside a packet eth0 has already counted.
    ///
    /// `tailscale0` is listed because it is the same tunnel as `wg0` under a
    /// different name.
    #[test]
    fn net_counts_a_wire_byte_once_however_many_devices_book_it() {
        let dev = "Inter-|   Receive\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n\
                   eth0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
                     lo: 9999 1 0 0 0 0 0 0 9999 2 0 0 0 0 0 0\n\
              docker0: 5555 1 0 0 0 0 0 0 5555 2 0 0 0 0 0 0\n\
            veth9a1b2c: 5555 1 0 0 0 0 0 0 5555 2 0 0 0 0 0 0\n\
                  wg0: 300 1 0 0 0 0 0 0 400 2 0 0 0 0 0 0\n\
           tailscale0: 300 1 0 0 0 0 0 0 400 2 0 0 0 0 0 0\n\
                 tun0: 300 1 0 0 0 0 0 0 400 2 0 0 0 0 0 0\n\
                 tap0: 300 1 0 0 0 0 0 0 400 2 0 0 0 0 0 0\n\
                bond0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
                  br0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
                vmbr0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
             eth0.100: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
              vlan100: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n";
        assert_eq!(parse_net_dev(dev), (1000, 2000));
    }

    /// The two questions asked of an interface name, and why one list cannot
    /// answer both: a bridge's bytes are a duplicate, while a bridge's address
    /// may be this machine's only address.
    #[test]
    fn a_stacked_device_loses_its_bytes_but_keeps_its_address() {
        for name in ["bond0", "br0", "vmbr0", "eth0.100", "vlan100"] {
            assert!(is_stacked(name), "{name}: the lower device already counted these bytes");
            assert!(!skip_iface(name), "{name} is where a host address lives");
        }
        // Neither this machine's traffic nor its address: container networks,
        // and tunnels whose payload leaves inside a packet eth0 has counted.
        for name in ["lo", "docker0", "veth9a1b2c", "br-6cd9538131d7", "virbr0", "wg0", "tun0", "tap0"] {
            assert!(skip_iface(name), "{name} is not this machine");
        }
        assert!(!skip_iface("eth0") && !is_stacked("eth0"), "the wire itself is what gets counted");
    }

    #[test]
    fn the_reported_address_is_the_public_one_whatever_the_kernel_lists_first() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let picked = |held: &[&str], transient: &[Ipv6Addr]| {
            let held: Vec<IpAddr> = held.iter().map(|s| ip(s)).collect();
            pick(&held, transient)
        };
        let pair = |v4: &str, v6: &str| (v4.to_owned(), v6.to_owned());

        // An LXC NAT guest: private v4 and a ULA on eth0, its public /128 on eth1.
        assert_eq!(
            picked(&["10.10.1.5", "fd42:43af:6613:5936::1", "2401:b60:1c::5"], &[]),
            pair("10.10.1.5", "2401:b60:1c::5")
        );
        // A TUN-mode proxy, a CGNAT overlay and the LAN all listed before the
        // public address.
        assert_eq!(
            picked(&["198.18.0.1", "100.64.0.9", "192.168.1.5", "203.0.113.7"], &[]),
            pair("203.0.113.7", "")
        );
        // With nothing public the kernel's order stands.
        assert_eq!(picked(&["192.168.1.5", "172.19.0.1"], &[]), pair("192.168.1.5", ""));

        // SLAAC with privacy extensions lists the temporary address first.
        let inet6 = "24098a1e3b4179f0a1b2c3d4e5f60718 02 40 00 01     eth0\n\
                     24098a1e3b4179f00211223344556677 02 40 00 00     eth0\n\
                     24098a1e3b4100000211223344556677 02 40 00 20     eth0\n\
                     fe80000000000000021122fffe334455 02 40 20 80     eth0\n";
        let transient = transient_v6(inet6);
        let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
        assert_eq!(
            transient,
            [v6("2409:8a1e:3b41:79f0:a1b2:c3d4:e5f6:718"), v6("2409:8a1e:3b41::211:2233:4455:6677")]
        );
        let slaac = [
            "2409:8a1e:3b41:79f0:a1b2:c3d4:e5f6:718",
            "2409:8a1e:3b41::211:2233:4455:6677",
            "2409:8a1e:3b41:79f0:211:2233:4455:6677",
        ];
        assert_eq!(picked(&slaac, &transient), pair("", "2409:8a1e:3b41:79f0:211:2233:4455:6677"));
        // A transient address is still better than none.
        assert_eq!(picked(&slaac[..1], &transient), pair("", slaac[0]));
    }

    #[test]
    fn only_globally_routable_addresses_count_as_public() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        for s in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "100.127.255.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.1",
            "192.0.0.4",
            "198.18.0.1",
            "198.19.255.1",
            "224.0.0.1",
            "fd42::1",
            "fc00::1",
            "fe80::1",
            "::1",
        ] {
            assert!(!is_public(ip(s)), "{s}");
        }
        for s in
            ["1.1.1.1", "100.128.0.1", "198.20.0.1", "192.0.1.1", "223.5.5.5", "2401:b60:1c::5", "3fff::1"]
        {
            assert!(is_public(ip(s)), "{s}");
        }
    }

    #[test]
    fn net_rate_is_zero_on_first_sample_and_after_a_reboot() {
        let mut c = Collector::new();
        let t0 = Instant::now();
        assert_eq!(c.net_rate(1000, 2000, t0), (0, 0));
        let t1 = t0 + std::time::Duration::from_secs(2);
        assert_eq!(c.net_rate(1200, 2400, t1), (100, 200));
        // Counter restarted: no negative value, no spurious spike.
        let t2 = t1 + std::time::Duration::from_secs(2);
        assert_eq!(c.net_rate(50, 60, t2), (0, 0));
    }

    /// Two independent guards reject a mount: its filesystem type, and whether
    /// its source looks like a device. Most entries trip both, so the table
    /// includes a line that only one of them catches.
    #[test]
    fn mounts_drop_pseudo_filesystems_and_duplicate_devices() {
        let mounts = parse_mounts(
            "/dev/vda1 / ext4 rw 0 0\n\
             proc /proc proc rw 0 0\n\
             tmpfs /run tmpfs rw 0 0\n\
             /dev/loop0 /snap/core24/1 squashfs ro 0 0\n\
             none /mnt/scratch ext4 rw 0 0\n\
             /dev/vda1 /var/lib/bind ext4 rw 0 0\n\
             overlay /var/lib/docker/overlay2/x/merged overlay rw 0 0\n\
             /dev/vdb1 /data xfs rw 0 0\n\
             /mnt/disk1:/mnt/disk2 /pool fuse.mergerfs rw 0 0\n\
             //nas/backup /mnt/nas cifs rw 0 0\n\
             tank/set1 /tank zfs rw 0 0\n\
             tank/set2 /tank/sub zfs rw 0 0\n",
        );
        // /snap/... is a real device holding a pseudo filesystem, rejected only
        // by the fstype list; one squashfs per snap would otherwise add a full
        // copy of each to the disk total. /mnt/scratch is the inverse, a real
        // filesystem whose source is not a path, caught only by the device
        // check. //nas/backup and the mergerfs pool are a third case: sources
        // that pass for a device while holding either remote storage or a second
        // view of mounts already counted. Only the fstype list excludes those,
        // and only `fuse` as a whole covers the pool. A block device behind a
        // fuse driver mounts as `fuseblk` and still counts.
        assert_eq!(mounts, vec!["/", "/data", "/tank"]);
    }

    /// `install.sh` runs this agent with `ProtectHome=yes`, which systemd
    /// implements by mounting a tmpfs over /home. Both rows remain in the table,
    /// but a path resolves to the upper one, so counting the row underneath
    /// would book the tmpfs's size -- half of RAM by default -- as that of a
    /// filesystem statvfs is never asked about.
    #[test]
    fn a_shadowed_filesystem_is_not_counted_as_the_one_mounted_over_it() {
        let table = "/dev/vda1 / ext4 rw 0 0\n\
                     /dev/vdb1 /home ext4 rw 0 0\n\
                     tmpfs /home tmpfs ro,size=409600k 0 0\n";
        assert_eq!(parse_mounts(table), vec!["/"]);
        // The shadowed mount is named, or the panel simply disagrees with df.
        assert_eq!(shadowed_mounts(table), vec!["/home"]);
        // A point mounted once is not shadowed, however many others exist.
        assert!(shadowed_mounts("/dev/vda1 / ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n").is_empty());
    }

    #[test]
    fn real_host_collection_is_sane() {
        let mut c = Collector::new();
        let f = c.facts();
        assert!(!f.hostname.is_empty() && f.cpu_cores >= 1 && f.mem_total > 0);
        // Whatever this host reports must parse, and a virtual bridge must not
        // be selected.
        assert!(f.ipv4.is_empty() || f.ipv4.parse::<std::net::Ipv4Addr>().is_ok());
        assert!(f.ipv6.is_empty() || f.ipv6.parse::<std::net::Ipv6Addr>().is_ok());
        assert!(!f.ipv4.is_empty() || !f.ipv6.is_empty(), "a reachable host has at least one address");
        // The prefix filter is the only guard keeping a docker bridge out.
        assert!(!f.ipv4.starts_with("172.17."), "a virtual bridge is not this machine's address");
        let m = c.collect();
        assert!(!m.boot_id.is_empty(), "boot_id drives reboot detection");
        assert!(m.mem_used > 0 && m.mem_used < m.mem_total);
        assert!(m.disk_used <= m.disk_total && m.disk_total > 0);
        assert!((0.0..=100.0).contains(&m.cpu));
    }
}

#[cfg(test)]
mod crosscheck {
    use super::*;

    /// The accuracy rule, checked against the tools it names. Constructed /proc
    /// text can only show that the arithmetic is right; it cannot show that the
    /// right field was read, which is the failure this agent exists to prevent.
    ///
    /// Every figure `free` and `df` report is compared, swap included: an
    /// omitted metric is one nothing verifies.
    ///
    /// The tolerance covers movement between the two readings and sits an order
    /// of magnitude below every wrong answer -- the root reserve `df` excludes
    /// and the page cache sysinfo counts as used are both gigabytes.
    ///
    /// Values are printed, so `cargo test crosscheck -- --nocapture` shows them.
    #[test]
    fn memory_and_disk_agree_with_free_and_df_on_this_machine() {
        let mut c = Collector::new();
        let m = c.collect();
        let gib = |b: u64| b as f64 / 1024.0 / 1024.0 / 1024.0;
        println!("mem  used={:.2}G total={:.2}G", gib(m.mem_used), gib(m.mem_total));
        println!("disk used={:.2}G total={:.2}G", gib(m.disk_used), gib(m.disk_total));
        println!("swap used={:.2}G total={:.2}G", gib(m.swap_used), gib(m.swap_total));
        println!("net  rx_total={} tx_total={}", m.net_rx_total, m.net_tx_total);

        const TOLERANCE: u64 = 64 * 1024 * 1024;
        let close = |ours: u64, theirs: u64, what: &str| {
            let drift = ours.abs_diff(theirs);
            assert!(drift < TOLERANCE, "{what}: ours={ours} theirs={theirs} drift={drift}");
        };

        // free(1) row "Mem:": its used column is total - available, which is
        // what MemAvailable reports.
        let free = tool("free", &["-b"]);
        let mut row = free.lines().nth(1).expect("free prints a Mem: row").split_whitespace().skip(1);
        let parse = |v: Option<&str>| v.expect("free column").parse::<u64>().expect("a byte count");
        assert_eq!(m.mem_total, parse(row.next()), "MemTotal is not free's total");
        close(m.mem_used, parse(row.next()), "memory");

        // free(1) row "Swap:": total, used, free. The tolerance is far tighter
        // than for memory because the miscount it catches -- subtracting
        // SwapCached -- is single-digit MiB, which the memory tolerance would
        // admit. Swap moves slowly enough for a megabyte to suffice.
        const SWAP_TOLERANCE: u64 = 1024 * 1024;
        let mut row = free.lines().nth(2).expect("free prints a Swap: row").split_whitespace().skip(1);
        assert_eq!(m.swap_total, parse(row.next()), "SwapTotal is not free's swap total");
        let theirs = parse(row.next());
        let drift = m.swap_used.abs_diff(theirs);
        assert!(drift < SWAP_TOLERANCE, "swap: ours={} theirs={theirs} drift={drift}", m.swap_used);

        // df(1) counts the root reserve as free, which is f_bfree rather than
        // f_bavail. Compared against a single filesystem, since df is asked
        // about one while the metric sums every mount.
        let (disk_total, disk_used) = disk_usage(&["/".to_owned()]);
        let df = tool("df", &["-B1", "--output=size,used", "/"]);
        let mut row = df.lines().nth(1).expect("df prints a data row").split_whitespace();
        let parse = |v: Option<&str>| v.expect("df column").parse::<u64>().expect("a byte count");
        assert_eq!(disk_total, parse(row.next()), "f_blocks is not df's size");
        close(disk_used, parse(row.next()), "disk");
    }

    /// A missing tool is a failure rather than grounds for passing quietly:
    /// this test is worthless if it can skip the comparison it exists for.
    fn tool(program: &str, args: &[&str]) -> String {
        let out = std::process::Command::new(program)
            .args(args)
            .env("LC_ALL", "C")
            .output()
            .unwrap_or_else(|e| panic!("{program}(1) is what these numbers are checked against: {e}"));
        assert!(out.status.success(), "{program} exited with {}", out.status);
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}
