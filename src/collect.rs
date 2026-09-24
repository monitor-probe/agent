//! Linux-only metric collection, read directly from /proc and statvfs.
//! sysinfo is not used: it misreports memory and disk for this purpose.

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;
use std::time::Instant;

use serde::Serialize;

/// Interfaces that carry neither this machine's traffic nor its identity:
/// loopback, container and VM networks, and tunnels whose bytes reach the wire
/// a second time inside their carrier.
///
/// `tailscale` belongs to the tunnel group for the same reason `wg` does: it is
/// WireGuard under another name, on an interface not called `wg0`. `fwln` is
/// the half of a Proxmox firewall's veth pair that `fwpr` does not match, and
/// `ifb` mirrors another interface's ingress for traffic shaping.
///
/// `gretap` and `erspan` are GRE carrying Ethernet; the kernel creates one of
/// each, idle, wherever the GRE module is loaded. `lxc` and `cilium` are
/// Cilium's pod veths and host devices, one veth per pod.
///
/// ponytail: a name list, so a GRE tap, or a tap or veth that is no bridge's
/// port, under a new name will be missed. Nothing in the kernel separates one
/// from a container's only link -- an LXC guest's veth, the tap of a rootless
/// container's pasta network -- and a guest counted as virtual would report no
/// traffic at all. Bridge ports and other tunnels are recognised by
/// [`counted_elsewhere`] whatever their name; the tunnel entries here also keep
/// their addresses out of [`addresses`]. `--iface` covers whatever neither
/// catches.
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
    "fwln",
    "ifb",
    "gretap",
    "erspan",
    "kube",
    "cali",
    "nerdctl",
    "lxc",
    "cilium",
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
    "ecryptfs",
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
    /// Names the span over which `net_rx_total` and `net_tx_total` readings
    /// are comparable. The hub only tests it for equality, and a change makes
    /// it re-baseline rather than book the difference. It is the kernel's boot
    /// id, which changes when the counters restart at zero, then `/` and a
    /// digest of the interfaces summed: an interface joining the sum within one
    /// boot -- a reclassified device, a changed `--iface` -- would otherwise
    /// have its lifetime bytes booked as traffic.
    pub boot_id: String,
    /// The `--iface` this agent runs with, empty for the default rules. Shown
    /// by the panel, which reinstalls with it.
    pub iface: String,
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

/// The traffic filter set by `--iface`: full interface names separated by
/// commas.
///
/// A plain entry makes the list the whole answer: nothing unlisted is counted.
/// Only the machine's owner knows which port faces the provider on a router,
/// where a forwarded byte crosses two real NICs, or whether a Proxmox host's
/// `vmbr0` alone should count. A listed name is counted whatever the built-in
/// rules say, since that is how `vmbr0` or `pppoe-wan` is chosen. An entry
/// starting with `-` removes that interface from what is counted otherwise,
/// which one batch command can apply across machines whose other NICs are named
/// differently. Exclusions win over inclusions.
#[derive(Default)]
pub struct Ifaces {
    spec: String,
    only: Vec<String>,
    skip: Vec<String>,
}

impl Ifaces {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let entries: Vec<&str> = spec.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        let mut ifaces = Self { spec: entries.join(","), ..Self::default() };
        for entry in entries {
            let (list, name) = match entry.strip_prefix('-') {
                Some(name) => (&mut ifaces.skip, name),
                None => (&mut ifaces.only, entry),
            };
            // Rejected rather than left to match nothing or everything: each
            // would silently change the totals. install.sh and the panel refuse
            // the same entries.
            if name.is_empty() || name.starts_with('-') || name.contains(char::is_whitespace) {
                return Err(format!(
                    "--iface: {entry:?} is not an interface name; give full names separated by commas"
                ));
            }
            list.push(name.to_owned());
        }
        Ok(ifaces)
    }

    fn counts(&self, sys: &Path, name: &str) -> bool {
        if self.skip.iter().any(|n| n == name) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.iter().any(|n| n == name);
        }
        !skip_iface(name) && !is_stacked(name) && !counted_elsewhere(sys, name)
    }
}

/// See [`Metrics::boot_id`]. The names are sorted, since /proc/net/dev lists a
/// recreated interface in a new position without the set having changed, and
/// hashed with FNV-1a, whose output no Rust release can alter.
///
/// ponytail: every change of the set costs the hub one interval on every
/// interface, including a freshly created one, whose counter starts at zero and
/// would have added correctly. Where counted interfaces come and go -- pods under
/// names no rule knows, pppN on a VPN server -- each event loses one interval.
/// Per-interface counters in the report, summed by the hub, would remove the
/// loss; an offset kept here would not, as it dies with the process and takes the
/// traffic of the downtime with it.
fn epoch<'a>(boot_id: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    // A newline cannot occur in an interface name, so no two sets join alike.
    let digest = names
        .join("\n")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3));
    format!("{boot_id}/{digest:016x}")
}

#[derive(Default)]
pub struct Collector {
    ifaces: Ifaces,
    prev_cpu: Option<(u64, u64)>,
    /// When the last sample was taken, and each counted interface's counters.
    prev_net_at: Option<Instant>,
    prev_net: HashMap<String, (u64, u64)>,
}

impl Collector {
    pub fn new(ifaces: Ifaces) -> Self {
        Self { ifaces, ..Self::default() }
    }

    /// The interfaces the traffic totals include at this moment.
    pub fn counted_ifaces(&self) -> Vec<String> {
        let dev = fs::read_to_string("/proc/net/dev").unwrap_or_default();
        self.counted(&dev).into_iter().map(|(name, ..)| name.to_owned()).collect()
    }

    fn counted<'a>(&self, dev: &'a str) -> Vec<(&'a str, u64, u64)> {
        net_dev(dev).filter(|(name, ..)| self.ifaces.counts(Path::new(SYS_NET), name)).collect()
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
        let dev = fs::read_to_string("/proc/net/dev").unwrap_or_default();
        let counted = self.counted(&dev);
        let (rx_total, tx_total) = totals(&counted);
        let boot_id = epoch(
            &read_trim("/proc/sys/kernel/random/boot_id").unwrap_or_default(),
            counted.iter().map(|(name, ..)| *name),
        );
        let (rx, tx) = self.net_rate(&counted, Instant::now());
        let (tcp, udp) = conn_counts();

        Metrics {
            boot_id,
            iface: self.ifaces.spec.clone(),
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

    /// Per interface, over those in both samples: one joining brings a lifetime
    /// counter that is not this interval's traffic, and one whose counter
    /// restarted moved backwards. Either would otherwise read as a burst in the
    /// history. Kept in memory only; a restarted agent reports no rate once.
    fn net_rate(&mut self, counted: &[(&str, u64, u64)], now: Instant) -> (u64, u64) {
        let rate = match self.prev_net_at {
            Some(t) => {
                let secs = now.saturating_duration_since(t).as_secs_f64();
                let (rx, tx) = counted
                    .iter()
                    .filter_map(|(name, rx, tx)| {
                        let (prx, ptx) = self.prev_net.get(*name)?;
                        Some((rx.saturating_sub(*prx), tx.saturating_sub(*ptx)))
                    })
                    .fold((0u64, 0u64), |(a, b), (r, t)| (a.saturating_add(r), b.saturating_add(t)));
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    ((rx as f64 / secs) as u64, (tx as f64 / secs) as u64)
                }
            }
            None => (0, 0),
        };
        self.prev_net_at = Some(now);
        self.prev_net = counted.iter().map(|(n, r, t)| ((*n).to_owned(), (*r, *t))).collect();
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
/// The hub applies the same ranges to the addresses this agent reports; the two
/// lists are to be changed together.
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

/// Sums the kernel's lifetime byte counters of the counted interfaces, one
/// count per byte on the wire.
fn totals(counted: &[(&str, u64, u64)]) -> (u64, u64) {
    counted.iter().fold((0, 0), |(rx, tx), (_, r, t)| (rx.saturating_add(*r), tx.saturating_add(*t)))
}

/// `(name, rx bytes, tx bytes)` for each interface in /proc/net/dev.
fn net_dev(text: &str) -> impl Iterator<Item = (&str, u64, u64)> {
    text.lines().skip(2).filter_map(|line| {
        let (name, rest) = line.split_once(':')?;
        let mut f = rest.split_whitespace().map(|v| v.parse::<u64>().ok());
        let rx = f.next()??;
        let tx = f.nth(7)??;
        Some((name.trim(), rx, tx))
    })
}

fn skip_iface(name: &str) -> bool {
    SKIP_IFACES.iter().any(|p| name.starts_with(p))
}

/// Stacked on top of another interface: bonds, bridges, VLAN children, and
/// OpenWrt's `pppoe-wan` over its WAN port. The kernel books one packet on
/// both, so counting these would double the traffic the hub bills. `pppoe-`
/// names PPPoE alone: a bare `ppp0` may be an LTE modem's only link.
///
/// [`counted_elsewhere`] finds the same from the kernel's links under any name.
/// The names still hold where sysfs cannot be read, and PPPoE has no such link
/// to the port it runs over.
///
/// A traffic rule only. These interfaces are where a host's own address most
/// often sits -- `vmbr0` on Proxmox, `bond0` where two ports form one link,
/// `pppoe-wan` on a router -- and whether bytes were already counted says
/// nothing about address ownership.
fn is_stacked(name: &str) -> bool {
    name.contains('.') || ["bond", "br", "vlan", "vmbr", "pppoe-"].iter().any(|p| name.starts_with(p))
}

const SYS_NET: &str = "/sys/class/net";

/// Link types of layer-3 tunnels as /sys/class/net/<name>/type prints them:
/// none (tun, WireGuard, Tailscale), ipip, ip6tnl, sit, gre, ip6gre. Read off
/// devices of each kind created on a 6.1 kernel. OpenVZ's `venet0`, a
/// container's only link, is void (65535) and stays out.
const TUNNEL_TYPES: &[&str] = &["65534", "768", "769", "776", "778", "823"];

/// Layer-2 tunnels that name themselves in `uevent`. GRE taps set no DEVTYPE
/// and are left to [`SKIP_IFACES`].
const TUNNEL_DEVTYPES: &[&str] = &["DEVTYPE=vxlan", "DEVTYPE=geneve"];

/// Devices that relay their ports' bytes and carry none of their own. Named in
/// `uevent` whether or not a port is attached, unlike the `lower_*` link, so an
/// LXD bridge whose last container has stopped stays out rather than joining
/// the sum with its lifetime counter.
const STACKED_DEVTYPES: &[&str] = &["DEVTYPE=bridge", "DEVTYPE=bond"];

/// Whether the kernel shows this interface's bytes counted on another one,
/// whatever it is called:
///
/// - a bridge or bond by DEVTYPE, or a `lower_*` link naming a device beneath
///   it in this namespace: a VLAN, a macvlan, a DSA switch port over its
///   conduit. The link is absent once a device moves to another namespace, so a
///   container whose only link is a macvlan still counts it.
/// - no hardware behind it, and a tunnel's link type or DEVTYPE: `he-ipv6`, a
///   mesh VPN or a user-named vxlan is caught as surely as `wg0`, since its
///   payload leaves again inside a packet the carrier counts. Hardware exempts
///   an LTE modem in raw-IP mode, which shares type none with WireGuard.
/// - no hardware behind it, and a bridge's port (`brport/`): a VM's tap such as
///   libvirt's `vnet0`, or a container's veth. What the guest sends out crosses
///   the physical port as well. A container's own only link is no bridge's port
///   inside the container and stays counted, as does a device under another
///   master -- a VRF, Open vSwitch -- whose uplink may be this very device.
///
/// A traffic rule only, like [`is_stacked`]: a tunnel broker's prefix on
/// `he-ipv6` is this machine's address. Unreadable sysfs leaves the name rules
/// alone in force.
///
/// ponytail: read afresh every sample, three or four sysfs calls for each
/// interface the name rules leave standing. That is one or two NICs on most
/// hosts; a hundred such interfaces would cost some 400 calls a second. Cache
/// the answer per ifindex if a host like that turns up.
fn counted_elsewhere(sys: &Path, name: &str) -> bool {
    let dev = sys.join(name);
    let read = |f: &str| fs::read_to_string(dev.join(f)).unwrap_or_default();
    let uevent = read("uevent");
    let devtype = |set: &[&str]| uevent.lines().any(|l| set.contains(&l));
    // Before the hardware test: a DSA switch port has both.
    let stacked = devtype(STACKED_DEVTYPES)
        || fs::read_dir(&dev).is_ok_and(|mut entries| {
            entries.any(|e| e.is_ok_and(|e| e.file_name().as_encoded_bytes().starts_with(b"lower_")))
        });
    if stacked {
        return true;
    }
    if dev.join("device").exists() {
        return false;
    }
    dev.join("brport").exists() || TUNNEL_TYPES.contains(&read("type").trim()) || devtype(TUNNEL_DEVTYPES)
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
        assert_eq!(Collector::default().cpu_percent(), 0.0);
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

    /// Totals over constructed /proc/net/dev text, with no sysfs to consult.
    fn sum(dev: &str, ifaces: &Ifaces) -> (u64, u64) {
        totals(
            &net_dev(dev).filter(|(n, ..)| ifaces.counts(Path::new("/nonexistent"), n)).collect::<Vec<_>>(),
        )
    }

    /// One byte on the wire, counted once. Every line but eth0 is that same
    /// byte booked a second time: bond, bridge, VLAN and PPPoE are stacked over
    /// it, a tunnel's payload leaves inside a packet eth0 has already counted,
    /// `fwln` carries a Proxmox guest's traffic on its way to eth0, and `ifb`
    /// mirrors eth0's ingress.
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
            fwln100i0: 300 1 0 0 0 0 0 0 400 2 0 0 0 0 0 0\n\
             ifb4eth0: 1000 1 0 0 0 0 0 0 1000 2 0 0 0 0 0 0\n\
                bond0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
                  br0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
                vmbr0: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
             eth0.100: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
              vlan100: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n\
            pppoe-wan: 1000 1 0 0 0 0 0 0 2000 2 0 0 0 0 0 0\n";
        assert_eq!(sum(dev, &Ifaces::default()), (1000, 2000));
    }

    /// The two questions asked of an interface name, and why one list cannot
    /// answer both: a bridge's bytes are a duplicate, while a bridge's address
    /// may be this machine's only address.
    #[test]
    fn a_stacked_device_loses_its_bytes_but_keeps_its_address() {
        for name in ["bond0", "br0", "vmbr0", "eth0.100", "vlan100", "pppoe-wan"] {
            assert!(is_stacked(name), "{name}: the lower device already counted these bytes");
            assert!(!skip_iface(name), "{name} is where a host address lives");
        }
        // Neither this machine's traffic nor its address: container networks,
        // and tunnels whose payload leaves inside a packet eth0 has counted.
        for name in [
            "lo",
            "docker0",
            "veth9a1b2c",
            "br-6cd9538131d7",
            "virbr0",
            "wg0",
            "tun0",
            "tap0",
            "fwln100i0",
            "ifb4eth0",
            "gretap0",
            "erspan0",
            "lxc9f2c1e",
            "cilium_host",
        ] {
            assert!(skip_iface(name), "{name} is not this machine");
        }
        assert!(!skip_iface("eth0") && !is_stacked("eth0"), "the wire itself is what gets counted");
    }

    /// The kernel's account of an interface decides, whatever it is called.
    /// Each entry mirrors what /sys/class/net held for that kind on a 6.1
    /// kernel: link type, the `device` link of hardware, the `lower_` link of a
    /// stacked device, DEVTYPE in `uevent`. A bridge is known by its DEVTYPE even
    /// after its last port has gone and taken the `lower_` link with it. The
    /// exempt ones are links a machine depends on that resemble a copy: a raw-IP
    /// LTE modem shares WireGuard's type none, OpenVZ's venet0 has no device, a
    /// macvlan moved into a container loses its `lower_` link there, a NIC in a
    /// bridge is a bridge's port as a VM's tap is, and a VRF's member has a
    /// master but is no bridge's port.
    #[test]
    fn the_kernel_tells_a_copy_whatever_the_interface_is_called() {
        let sys = std::env::temp_dir().join(format!("monitor-agent-sys-{}", std::process::id()));
        // Left behind by a failed run under a reused PID.
        let _ = fs::remove_dir_all(&sys);
        for (name, ty, extra) in [
            ("he-ipv6", 776, &[][..]),
            ("nebula1", 65534, &[]),
            ("gre1", 778, &[]),
            ("vx100", 1, &["DEVTYPE=vxlan"]),
            ("lan", 1, &["lower_eth0"]),
            ("lxdbr0", 1, &["DEVTYPE=bridge"]),
            ("uplink", 1, &["DEVTYPE=bond"]),
            ("wan", 1, &["device", "lower_eth0"]),
            ("wwan0", 65534, &["device"]),
            ("venet0", 65535, &[]),
            ("mv0", 1, &[]),
            ("eth0", 1, &["device"]),
            ("vnet0", 1, &["brport"]),
            ("eno1", 1, &["device", "brport"]),
            ("up1", 1, &["master"]),
        ] {
            let dir = sys.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("type"), format!("{ty}\n")).unwrap();
            for e in extra {
                match e.strip_prefix("DEVTYPE=") {
                    Some(_) => fs::write(dir.join("uevent"), format!("{e}\nINTERFACE={name}\n")).unwrap(),
                    None => fs::create_dir(dir.join(e)).unwrap(),
                }
            }
        }
        // Tunnels by link type and DEVTYPE; a user-named bridge and a DSA
        // switch port by their link to the device beneath; a bridge with no
        // port left and a bond by DEVTYPE; a VM's tap by its bridge.
        for name in ["he-ipv6", "nebula1", "gre1", "vx100", "lan", "wan", "lxdbr0", "uplink", "vnet0"] {
            assert!(counted_elsewhere(&sys, name), "{name}: another interface counts these bytes");
        }
        for name in ["wwan0", "venet0", "mv0", "eth0", "eno1", "up1", "absent0"] {
            assert!(!counted_elsewhere(&sys, name), "{name} is this machine's own link");
        }
        fs::remove_dir_all(&sys).unwrap();
    }

    /// A router forwards each byte across two real NICs, so only its owner can
    /// name the one facing the provider. A name in `--iface` is counted whatever
    /// the built-in rules say; `-` entries come off the top of either.
    #[test]
    fn iface_names_what_is_counted_over_every_built_in_rule() {
        // 1000 bytes downloaded through the router: in on the WAN port inside
        // PPPoE, out through the LAN port. eth1.7 is a VLAN on the WAN port.
        let dev = "header\nheader\n\
                   eth0: 50 1 0 0 0 0 0 0 1000 2 0 0 0 0 0 0\n\
                   eth1: 1008 1 0 0 0 0 0 0 60 2 0 0 0 0 0 0\n\
                 eth1.7: 500 1 0 0 0 0 0 0 30 2 0 0 0 0 0 0\n\
              pppoe-wan: 1000 1 0 0 0 0 0 0 52 2 0 0 0 0 0 0\n\
                  vmbr0: 7 1 0 0 0 0 0 0 9 2 0 0 0 0 0 0\n";
        let with = |spec: &str| sum(dev, &Ifaces::parse(spec).unwrap());
        assert_eq!(with(""), (1058, 1060), "by default both real ports count the forwarded bytes");
        assert_eq!(with("pppoe-wan"), (1000, 52), "a listed interface counts though it is stacked");
        assert_eq!(with("vmbr0"), (7, 9));
        assert_eq!(with("eth1.7"), (500, 30));
        assert_eq!(with("-eth0"), (1008, 60), "an exclusion comes off the default set");
        assert_eq!(with("eth0,eth1,-eth0"), (1008, 60), "an exclusion wins over a listing");
        assert_eq!(with("eth9"), (0, 0), "an absent interface counts nothing rather than everything");

        // Each would count nothing, everything, or not what it says.
        for bad in ["eth0 eth1", "-", "eth0,-", "--eth0"] {
            assert!(Ifaces::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    /// Any change to which interfaces are summed, within one boot, must make the
    /// hub re-baseline rather than book the difference between two sums: a
    /// device the rules reclassify, a changed `--iface`.
    #[test]
    fn the_epoch_changes_whenever_the_summed_set_does() {
        let e = |names: &[&str]| epoch("boot", names.iter().copied());
        assert!(e(&["eth0"]).starts_with("boot/"), "a reboot still changes it");
        assert_ne!(e(&["eth0"]), e(&["eth0", "lxdbr0"]));
        assert_ne!(e(&["eth0"]), e(&["eth1"]));
        assert_ne!(e(&["eth0"]), e(&[]));
        assert_eq!(e(&["eth1", "eth0"]), e(&["eth0", "eth1"]), "listing order is not a different set");
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
    fn net_rate_counts_each_interface_against_its_own_last_reading() {
        let mut c = Collector::default();
        let t0 = Instant::now();
        let at = |secs| t0 + std::time::Duration::from_secs(secs);
        assert_eq!(c.net_rate(&[("eth0", 1000, 2000)], t0), (0, 0));
        assert_eq!(c.net_rate(&[("eth0", 1200, 2400)], at(2)), (100, 200));
        // Counter restarted: no negative value, no spurious spike.
        assert_eq!(c.net_rate(&[("eth0", 50, 60)], at(4)), (0, 0));
        // An interface joined with its lifetime counter: not a burst of
        // traffic, and the others keep their rate.
        assert_eq!(c.net_rate(&[("eth0", 250, 460), ("eth1", 9_000_000, 9_000_000)], at(6)), (100, 200));
        assert_eq!(c.net_rate(&[("eth0", 450, 860), ("eth1", 9_000_200, 9_000_400)], at(8)), (200, 400));
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
             /home/.ecryptfs/u/.Private /home/u ecryptfs rw 0 0\n\
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
        // fuse driver mounts as `fuseblk` and still counts. The ecryptfs row is
        // a fourth: a stacked mount whose source is a directory on the filesystem
        // beneath it, so it passes the device check and carries a source of its
        // own past the dedup, while statvfs reports that filesystem again.
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
        let mut c = Collector::default();
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
        // Read through the real /sys: a link-type test misfiring on this host's
        // NIC would leave nothing counted.
        assert!(!c.counted_ifaces().is_empty(), "a reachable host counts at least one interface");
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
        let mut c = Collector::default();
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
