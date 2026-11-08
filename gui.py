#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mininet Network Visualizer v2 - live, web-based network view for teaching.

Drop-in replacement for the original gui.py. Existing topology scripts keep
working unchanged:

    from gui import start_visualizer
    net.start()
    start_visualizer(net, port=9090)

Everything below is detected live from the running network, so the same GUI
works for VLAN, VPN, ACL/firewall, routing and traffic labs:

  * Tree layout (core -> distribution -> access -> hosts), force layout, pan/zoom
  * Link state (up/down) and live throughput from interface counters
  * Grouping/colouring by VLAN (OVS access/trunk ports, 802.1Q sub-interfaces),
    by subnet, or by custom groups you define
  * Tunnels / VPNs: IPsec (xfrm), WireGuard, GRE, VXLAN, IPIP, OpenVPN/TUN/TAP
  * Access control: OpenFlow drop rules on OVS switches and iptables
    DROP/REJECT rules on hosts, with live drop counters
  * Active TCP/UDP flows between hosts, classified (Web, SSH, DNS, VoIP,
    iperf, VPN ...) and animated along their path
  * Per-node live details: interfaces, routes, ARP, sockets, firewall rules,
    NAT, IPsec policies, tc qdiscs, OpenFlow tables, MAC tables, port stats
  * Ping test and all-pairs reachability matrix
  * PNG export, save/load layout, light/dark theme

Optional annotations from a topology script, for anything not auto-detected:

    from gui import start_visualizer, get_visualizer
    start_visualizer(net)
    viz = get_visualizer()
    viz.add_group('DMZ', ['h3', 'h6'], color='#f59e0b')
    viz.add_tunnel('h1', 'h7', label='Site-to-site VPN')
    viz.set_role('h3', 'firewall')   # host, server, router, firewall, nat, vpn-gw
    viz.add_traffic_class('Video', '5004-5005', proto='udp', color='#e11d48')
    viz.annotate_node('h6', 'Marketing file server')
    viz.annotate_link('s3', 's4', 'Core uplink')
    viz.log_event('ACL applied on s3', level='warn')

Security: the server runs as root and can run ping inside hosts, so it only
listens on 127.0.0.1 by default. To reach it from another machine, use an SSH
tunnel (ssh -L 9090:localhost:9090 user@vm) or start Mininet with
    sudo MNVIZ_BIND=0.0.0.0 mn --custom ...

Requires Python 3 (as used by current Mininet releases).
"""

import sys

if sys.version_info[0] < 3:
    raise ImportError('gui.py requires Python 3')

import hashlib
import http.server
import ipaddress
import json
import os
import re
import shlex
import shutil
import socketserver
import subprocess
import threading
import time
import traceback
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlparse

__all__ = ['start_visualizer', 'get_visualizer', 'stop_visualizer',
           'MininetVisualizer']

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TRAFFIC_CLASSES = [
    {'name': 'VoIP (SIP/RTP)', 'proto': 'udp',
     'ports': [(5060, 5061), (10000, 20000), (16384, 32767)], 'color': '#a855f7'},
    {'name': 'SIP (TCP)', 'proto': 'tcp', 'ports': [(5060, 5061)], 'color': '#a855f7'},
    {'name': 'DNS', 'proto': 'any', 'ports': [(53, 53)], 'color': '#14b8a6'},
    {'name': 'SSH', 'proto': 'tcp', 'ports': [(22, 22)], 'color': '#06b6d4'},
    {'name': 'Web', 'proto': 'tcp',
     'ports': [(80, 80), (443, 443), (8000, 8000), (8080, 8080)], 'color': '#3b82f6'},
    {'name': 'VPN', 'proto': 'any',
     'ports': [(500, 500), (4500, 4500), (1194, 1194), (51820, 51820)], 'color': '#ec4899'},
    {'name': 'iperf', 'proto': 'any', 'ports': [(5001, 5001), (5201, 5201)], 'color': '#f59e0b'},
]
OTHER_TCP = {'name': 'Other TCP', 'proto': 'tcp', 'ports': [], 'color': '#64748b'}
OTHER_UDP = {'name': 'Other UDP', 'proto': 'udp', 'ports': [], 'color': '#f97316'}

# Red is reserved for drops / link down, so it is not in the group palette.
GROUP_PALETTE = ['#22c55e', '#3b82f6', '#f59e0b', '#ec4899', '#14b8a6',
                 '#a855f7', '#84cc16', '#06b6d4', '#f97316', '#6366f1',
                 '#eab308', '#0ea5e9']

TUNNEL_COLORS = {
    'IPsec': '#e11d48', 'WireGuard': '#7c3aed', 'GRE': '#0891b2',
    'VXLAN': '#0d9488', 'IPIP': '#0284c7', 'OpenVPN/TUN': '#c026d3',
    'Geneve': '#0d9488', 'VPN': '#db2777',
}

# Kernel fallback devices that exist in every namespace once a module is loaded.
_FALLBACK_DEVS = {'gre0', 'gretap0', 'erspan0', 'tunl0', 'sit0', 'ip6tnl0',
                  'ip6gre0', 'ip_vti0', 'ip6_vti0', 'ovs-system', 'lo'}

_TUN_KINDS = [('wireguard', 'WireGuard'), ('vxlan', 'VXLAN'),
              ('gretap', 'GRE'), ('ip6gretap', 'GRE'), ('ip6gre', 'GRE'),
              ('erspan', 'GRE'), ('gre', 'GRE'), ('ipip', 'IPIP'),
              ('sit', 'IPIP'), ('ip6tnl', 'IPIP'), ('geneve', 'Geneve'),
              ('vti', 'IPsec'), ('vti6', 'IPsec'), ('xfrm', 'IPsec')]

OF_PROTOS = 'OpenFlow10,OpenFlow11,OpenFlow12,OpenFlow13'

SLOW_SCRIPT = (
    'echo @@LINK; ip -o -d link show 2>/dev/null; '
    'echo @@ADDR; ip -o addr show 2>/dev/null; '
    'echo @@XFRM; ip xfrm state 2>/dev/null; '
    'echo @@WG; wg show all endpoints 2>/dev/null; '
    'echo @@FWD; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'
)

FAST_HOST_SCRIPT = (
    'echo @@CONN; ss -tunp 2>/dev/null; '
    'echo @@LISTEN; ss -tulnp 2>/dev/null; '
    'echo @@IPT; iptables -nvxL 2>/dev/null'
)

HOST_DETAIL_SCRIPT = (
    'echo "@@Addresses"; ip -br addr show 2>/dev/null || ip addr show; '
    'echo "@@Routing table"; ip route show 2>/dev/null; '
    'ip -6 route show 2>/dev/null | grep -v "^fe80" | grep -v "^multicast"; '
    'echo "@@ARP / neighbour table"; ip neigh show 2>/dev/null; '
    'echo "@@Listening sockets"; ss -tulnp 2>/dev/null; '
    'echo "@@Active connections"; ss -tunp 2>/dev/null; '
    'echo "@@Firewall (iptables filter)"; iptables -nvL --line-numbers 2>/dev/null; '
    'echo "@@NAT (iptables nat)"; iptables -t nat -nvL 2>/dev/null; '
    'echo "@@IPsec SAs"; ip xfrm state 2>/dev/null; '
    'echo "@@IPsec policies"; ip xfrm policy 2>/dev/null; '
    'echo "@@WireGuard"; wg show 2>/dev/null; '
    'echo "@@Traffic control (tc)"; tc qdisc show 2>/dev/null; '
    'echo "@@IP forwarding"; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null'
)

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

_NSENTER = shutil.which('nsenter')
_MNEXEC = shutil.which('mnexec')
_OVS_VSCTL = shutil.which('ovs-vsctl')
_OVS_OFCTL = shutil.which('ovs-ofctl')
_OVS_APPCTL = shutil.which('ovs-appctl')


def _readlink(path):
    try:
        return os.readlink(path)
    except OSError:
        return None


_SELF_NETNS = _readlink('/proc/self/ns/net')


def _netns(pid):
    if pid is None:
        return None
    return _readlink('/proc/%d/ns/net' % int(pid))


def _run(argv, timeout=4.0):
    """Run a command and return stdout as text ('' on any failure)."""
    try:
        res = subprocess.run(argv, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=timeout)
        return res.stdout.decode('utf-8', 'replace')
    except Exception:
        return ''


def _ns_prefix(pid):
    """Command prefix that runs inside the network namespace of pid.

    Mininet's node.cmd() is NOT thread-safe (it shares the node's shell with
    the CLI), so the visualizer never uses it and enters the namespace itself.
    """
    ns = _netns(pid)
    if ns is None:
        return None
    if ns == _SELF_NETNS:
        return []
    if _NSENTER:
        return [_NSENTER, '-t', str(int(pid)), '-n']
    if _MNEXEC:
        return [_MNEXEC, '-a', str(int(pid))]
    return None


def _sh(pid, script, timeout=4.0):
    prefix = _ns_prefix(pid)
    if prefix is None:
        return ''
    return _run(prefix + ['sh', '-c', script], timeout)


def _sections(text, markers):
    res = dict((m, '') for m in markers)
    cur, buf = None, []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('@@') and s[2:] in markers:
            if cur:
                res[cur] = '\n'.join(buf)
            cur, buf = s[2:], []
        elif cur:
            buf.append(line)
    if cur:
        res[cur] = '\n'.join(buf)
    return res


def _sections_ordered(text):
    out, cur, buf = [], None, []
    for line in text.splitlines():
        if line.startswith('@@'):
            if cur is not None:
                out.append((cur, '\n'.join(buf).strip('\n')))
            cur, buf = line[2:].strip(), []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out.append((cur, '\n'.join(buf).strip('\n')))
    return [(t, b) for t, b in out if b.strip()]


def _read_netdev(pid):
    """Interface counters for the namespace of pid (no subprocess needed)."""
    try:
        with open('/proc/%d/net/dev' % int(pid)) as f:
            lines = f.read().splitlines()[2:]
    except Exception:
        return {}
    res = {}
    for line in lines:
        if ':' not in line:
            continue
        name, data = line.split(':', 1)
        f = data.split()
        if len(f) < 12:
            continue
        try:
            # rx_bytes, rx_packets, rx_drop, tx_bytes, tx_packets, tx_drop
            res[name.strip()] = (int(f[0]), int(f[1]), int(f[3]),
                                 int(f[8]), int(f[9]), int(f[11]))
        except ValueError:
            pass
    return res


def _operstate(ifname):
    try:
        with open('/sys/class/net/%s/operstate' % ifname) as f:
            return f.read().strip()
    except Exception:
        return None


def _split_addr(s):
    if s.startswith('['):
        host, _, port = s[1:].partition(']:')
    else:
        host, _, port = s.rpartition(':')
    host = host.split('%', 1)[0]
    if host.lower().startswith('::ffff:'):
        host = host[7:]
    try:
        port = int(port)
    except ValueError:
        port = 0
    return host, port


def _parse_ss(text):
    out = []
    for line in text.splitlines():
        f = line.split()
        if len(f) < 6 or f[0] not in ('tcp', 'udp'):
            continue
        lip, lport = _split_addr(f[4])
        pip, pport = _split_addr(f[5])
        m = re.search(r'\(\("([^"]+)"', line)
        out.append({'proto': f[0], 'state': f[1], 'lip': lip, 'lport': lport,
                    'pip': pip, 'pport': pport, 'proc': m.group(1) if m else ''})
    return out


def _parse_ipt(text):
    """Return (dropped_packets, blocking_rules) from `iptables -nvxL`."""
    drops = rules = 0
    for line in text.splitlines():
        m = re.match(r'Chain (\S+) \(policy (\w+) (\d+) packets', line)
        if m:
            if m.group(2) in ('DROP', 'REJECT'):
                drops += int(m.group(3))
                rules += 1
            continue
        f = line.split()
        if len(f) >= 3 and f[0].isdigit() and f[2] in ('DROP', 'REJECT'):
            drops += int(f[0])
            rules += 1
    return drops, rules


def _parse_flows(text):
    """Return (flow_count, drop_rules, dropped_packets) from dump-flows."""
    total = drop_rules = drop_pkts = 0
    for line in text.splitlines():
        if 'actions=' not in line:
            continue
        total += 1
        acts = line.rsplit('actions=', 1)[1].strip()
        if acts in ('drop', '', 'clear_actions'):
            drop_rules += 1
            m = re.search(r'n_packets=(\d+)', line)
            if m:
                drop_pkts += int(m.group(1))
    return total, drop_rules, drop_pkts


def _parse_links(text):
    ifs = {}
    for line in text.splitlines():
        m = re.match(r'^\d+:\s+([^:@\s]+)(?:@(\S+?))?:\s+<([^>]*)>(.*)$', line)
        if not m:
            continue
        name, _parent, flags, rest = m.groups()
        flags = set(flags.split(','))
        kind = remote = vlan = None
        if name not in _FALLBACK_DEVS:
            if re.search(r'\btun type (tun|tap)\b', rest):
                kind = 'OpenVPN/TUN'
            else:
                for key, label in _TUN_KINDS:
                    if re.search(r'(?:^|\s)%s(?:\s|$)' % re.escape(key), rest):
                        kind = label
                        break
            mv = re.search(r'\bvlan protocol 802\.1[Qq]\S*\s+id\s+(\d+)', rest)
            if mv:
                vlan = int(mv.group(1))
            mr = re.search(r'\bremote\s+([0-9a-fA-F.:]+)', rest)
            if mr and mr.group(1) not in ('any', '0.0.0.0'):
                remote = mr.group(1)
        mac = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', rest)
        ifs[name] = {
            'flags': sorted(flags),
            'up': 'UP' in flags and 'LOWER_UP' in flags,
            'kind': kind, 'remote': remote, 'vlan': vlan,
            'mac': mac.group(1) if mac else None, 'ips': [],
        }
    return ifs


def _parse_addrs(text):
    res = defaultdict(list)
    for line in text.splitlines():
        m = re.match(r'^\d+:\s+([^:@\s]+)\S*\s+(inet6?)\s+(\S+)(?:\s+peer\s+(\S+))?', line)
        if not m:
            continue
        name, fam, addr, peer = m.groups()
        if name == 'lo' or (fam == 'inet6' and addr.lower().startswith('fe80')):
            continue
        cidr = addr if '/' in addr else addr + ('/32' if fam == 'inet' else '/128')
        res[name].append({'cidr': cidr, 'ip': addr.split('/')[0], 'fam': fam,
                          'peer': peer.split('/')[0] if peer else None})
    return res


def _ovs_atom(v):
    if isinstance(v, list) and len(v) == 2 and v[0] in ('set', 'uuid', 'named-uuid'):
        return v[1]
    return v


def _parse_ports(spec):
    if spec is None:
        return []
    if isinstance(spec, int):
        return [(spec, spec)]
    if isinstance(spec, str):
        out = []
        for part in spec.replace(' ', '').split(','):
            if not part:
                continue
            if '-' in part:
                a, b = part.split('-', 1)
                out.append((int(a), int(b)))
            else:
                out.append((int(part), int(part)))
        return out
    if isinstance(spec, tuple) and len(spec) == 2 and all(isinstance(x, int) for x in spec):
        return [spec]
    out = []
    for s in spec:
        out.extend(_parse_ports(s))
    return out


def _port_allows(p):
    """VLANs a switch port carries: a set, or None meaning 'all VLANs'."""
    if p is None:
        return None
    if p['trunks']:
        s = set(p['trunks'])
        if p['tag'] is not None:
            s.add(p['tag'])
        return s
    if p['tag'] is not None:
        return {p['tag']}
    return None


def _intersect(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a & b


def _port_desc(p):
    if p is None:
        return None
    if p['trunks']:
        d = 'trunk ' + ','.join(str(t) for t in p['trunks'])
        if p['tag'] is not None:
            d += ' (native %d)' % p['tag']
        return d
    if p['tag'] is not None:
        return 'access VLAN %d' % p['tag']
    return 'no VLAN config (carries all)'


def _is_ovs(sw):
    return 'OVS' in type(sw).__name__ or hasattr(sw, 'vsctl')


def _name(x):
    return x.name if hasattr(x, 'name') else str(x)


def _link_id(ia, ib):
    a, b = sorted((ia, ib))
    return '%s|%s' % (a, b)


# ---------------------------------------------------------------------------
# Visualizer
# ---------------------------------------------------------------------------

class MininetVisualizer(object):
    """Live web visualizer for a running Mininet network."""

    STATE_TTL = 1.0   # seconds a computed live state is reused
    SLOW_TTL = 4.0    # seconds interface/tunnel/VLAN data is reused

    def __init__(self, net, port=9090, host=None):
        self.net = net
        self.port = int(port)
        self.bind = host if host is not None else os.environ.get('MNVIZ_BIND', '127.0.0.1')
        self.lock = threading.RLock()
        self._pool = ThreadPoolExecutor(max_workers=8)

        # User annotations
        self.custom_groups = []
        self.tunnels_manual = []
        self.node_notes = {}
        self.link_notes = {}
        self.roles = {}
        self.user_classes = []

        # Live state bookkeeping
        self.events = deque(maxlen=300)
        self.event_seq = 0
        self._prev_ctr = {}
        self._prev_drops = {}
        self._prev_link_up = {}
        self._prev_conns = set()
        self._prev_tunnels = set()
        self._first = True
        self._slow = (0.0, None)
        self._state = (0.0, None)

        self.httpd = None
        self.thread = None
        self._event('Visualizer started for %d hosts, %d switches' %
                    (len(net.hosts), len(net.switches)))

    # ---- public annotation API -------------------------------------------

    def add_group(self, name, members, color=None):
        """Define a custom group (department, DMZ, VPN site...)."""
        members = [_name(m) for m in members]
        with self.lock:
            self.custom_groups = [g for g in self.custom_groups if g['name'] != name]
            self.custom_groups.append({'name': name, 'members': members, 'color': color})
        return self

    def add_tunnel(self, a, b, label='VPN', color=None, kind='VPN'):
        """Draw a logical tunnel/overlay between two nodes."""
        with self.lock:
            self.tunnels_manual.append({'a': _name(a), 'b': _name(b), 'label': label,
                                        'color': color, 'kind': kind})
        return self

    def annotate_node(self, node, text):
        with self.lock:
            self.node_notes[_name(node)] = text
        return self

    def annotate_link(self, a, b, text):
        with self.lock:
            self.link_notes[tuple(sorted((_name(a), _name(b))))] = text
        return self

    def set_role(self, node, role):
        """Role controls the icon: host, server, router, firewall, nat, vpn-gw."""
        with self.lock:
            self.roles[_name(node)] = role
        return self

    def add_traffic_class(self, name, ports, proto='any', color=None):
        """Classify flows, e.g. add_traffic_class('Video', '5004-5005', 'udp')."""
        cls = {'name': name, 'proto': proto, 'ports': _parse_ports(ports),
               'color': color or GROUP_PALETTE[len(self.user_classes) % len(GROUP_PALETTE)]}
        with self.lock:
            self.user_classes = [c for c in self.user_classes if c['name'] != name]
            self.user_classes.insert(0, cls)
        return self

    def log_event(self, text, level='info'):
        self._event(text, level)
        return self

    # ---- events ----------------------------------------------------------

    def _event(self, text, level='info'):
        with self.lock:
            self.event_seq += 1
            self.events.append({'seq': self.event_seq, 't': time.time(),
                                'level': level, 'text': text})

    # ---- topology ----------------------------------------------------------

    def _all_nodes(self):
        return list(self.net.controllers) + list(self.net.switches) + list(self.net.hosts)

    def _node_by_name(self, name):
        for n in self._all_nodes():
            if n.name == name:
                return n
        return None

    def get_topology(self):
        nodes, links = [], []
        for c in self.net.controllers:
            nodes.append({'id': c.name, 'type': 'controller', 'cls': type(c).__name__,
                          'ctrl': '%s:%s' % (getattr(c, 'ip', '?'), getattr(c, 'port', '?'))})
        for s in self.net.switches:
            nodes.append({'id': s.name, 'type': 'switch', 'cls': type(s).__name__,
                          'dpid': getattr(s, 'dpid', None)})
        for h in self.net.hosts:
            nodes.append({'id': h.name, 'type': 'host', 'cls': type(h).__name__})
        for link in self.net.links:
            i1, i2 = link.intf1, link.intf2
            params = {}
            p = getattr(i1, 'params', None) or {}
            for k in ('bw', 'delay', 'jitter', 'loss', 'max_queue_size'):
                if p.get(k) is not None:
                    params[k] = p.get(k)
            links.append({'id': _link_id(i1.name, i2.name), 'a': i1.node.name,
                          'b': i2.node.name, 'ia': i1.name, 'ib': i2.name,
                          'params': params})
        sig_src = '|'.join(sorted(n['id'] for n in nodes)) + '#' + \
            '|'.join(sorted(l['id'] for l in links))
        sig = hashlib.sha1(sig_src.encode()).hexdigest()[:12]
        return {'nodes': nodes, 'links': links, 'sig': sig}

    # Backwards compatibility with the original class
    def generate_topology_data(self):
        return self.get_topology()

    # ---- slow data: interfaces, addresses, tunnels, OVS VLAN config ------

    def _get_slow(self, force=False):
        with self.lock:
            t, data = self._slow
            if data is None or force or time.time() - t > self.SLOW_TTL:
                data = self._collect_slow()
                self._slow = (time.time(), data)
            return data

    def _ovs_ports(self):
        if not _OVS_VSCTL or not any(_is_ovs(s) for s in self.net.switches):
            return {}
        out = _run([_OVS_VSCTL, '--format=json', '--columns=name,tag,trunks,vlan_mode',
                    'list', 'Port'], timeout=4)
        try:
            d = json.loads(out)
        except Exception:
            return {}
        heads = d.get('headings', [])
        res = {}
        for row in d.get('data', []):
            r = dict(zip(heads, row))
            name = _ovs_atom(r.get('name'))
            tag = _ovs_atom(r.get('tag'))
            trunks = _ovs_atom(r.get('trunks'))
            mode = _ovs_atom(r.get('vlan_mode'))
            if isinstance(tag, list):
                tag = tag[0] if tag else None
            if trunks is None:
                trunks = []
            elif not isinstance(trunks, list):
                trunks = [trunks]
            if isinstance(mode, list):
                mode = mode[0] if mode else None
            try:
                res[str(name)] = {'tag': int(tag) if tag is not None else None,
                                  'trunks': sorted(int(t) for t in trunks), 'mode': mode}
            except (TypeError, ValueError):
                pass
        return res

    def _collect_slow(self):
        parsed_ns = {}
        per_node = {}
        switch_names = set(s.name for s in self.net.switches)
        for n in list(self.net.switches) + list(self.net.hosts):
            pid = getattr(n, 'pid', None)
            ns = _netns(pid)
            if ns is None:
                per_node[n.name] = None
                continue
            if ns not in parsed_ns:
                raw = _sh(pid, SLOW_SCRIPT, timeout=5)
                sec = _sections(raw, ('LINK', 'ADDR', 'XFRM', 'WG', 'FWD'))
                ifs = _parse_links(sec['LINK'])
                for ifn, addrs in _parse_addrs(sec['ADDR']).items():
                    ifs.setdefault(ifn, {'flags': [], 'up': True, 'kind': None, 'remote': None,
                                         'vlan': None, 'mac': None, 'ips': []})
                    ifs[ifn]['ips'] = addrs
                xfrm = re.findall(r'^src (\S+) dst (\S+)', sec['XFRM'], re.M)
                wg = []
                for line in sec['WG'].splitlines():
                    parts = line.split('\t')
                    if len(parts) >= 3 and parts[2] and parts[2] != '(none)':
                        wg.append((parts[0], _split_addr(parts[2])[0]))
                parsed_ns[ns] = {'ifaces': ifs, 'xfrm': xfrm, 'wg': wg,
                                 'fwd': sec['FWD'].strip() == '1'}
            pn = parsed_ns[ns]
            in_root = (ns == _SELF_NETNS)
            if in_root or n.name in switch_names:
                own = set(i for i in n.intfNames() if i != 'lo')
                ifaces = dict((k, v) for k, v in pn['ifaces'].items() if k in own)
            else:
                ifaces = dict((k, v) for k, v in pn['ifaces'].items() if k != 'lo')
            per_node[n.name] = {
                'ns': ns, 'in_root': in_root, 'ifaces': ifaces, 'fwd': pn['fwd'],
                'xfrm': [] if in_root else pn['xfrm'],
                'wg': [] if in_root else pn['wg'],
            }
        ipmap = {}
        for h in self.net.hosts:
            nd = per_node.get(h.name)
            if nd:
                for ifn, inf in nd['ifaces'].items():
                    for a in inf['ips']:
                        ipmap.setdefault(a['ip'], (h.name, ifn))
            try:
                ip = h.IP()
                if ip:
                    ipmap.setdefault(ip, (h.name, h.defaultIntf().name))
            except Exception:
                pass
        return {'nodes': per_node, 'ovs': self._ovs_ports(), 'ipmap': ipmap}

    # ---- classification ------------------------------------------------------

    def _classes(self):
        return self.user_classes + DEFAULT_TRAFFIC_CLASSES

    def _classify(self, proto, p1, p2):
        for c in self._classes():
            if c['proto'] not in ('any', proto):
                continue
            for lo, hi in c['ports']:
                if lo <= p1 <= hi or lo <= p2 <= hi:
                    return c
        return OTHER_TCP if proto == 'tcp' else OTHER_UDP

    # ---- live state ------------------------------------------------------------

    def get_state(self, since=0):
        with self.lock:
            t, st = self._state
            if st is None or time.time() - t > self.STATE_TTL:
                st = self._compute_state()
                self._state = (time.time(), st)
            evs = [e for e in self.events if e['seq'] > since]
            seq = self.event_seq
        out = dict(st)
        out['events'] = evs
        out['seq'] = seq
        return out

    def _role(self, node, ntype, nd):
        if node.name in self.roles:
            return self.roles[node.name]
        if ntype != 'host':
            return ntype
        cls = type(node).__name__.lower()
        if 'nat' in cls:
            return 'nat'
        if 'firewall' in cls:
            return 'firewall'
        if 'router' in cls:
            return 'router'
        if nd and nd.get('fwd'):
            count = 0
            for inf in nd['ifaces'].values():
                if inf.get('kind'):
                    continue
                if any(a['fam'] == 'inet' for a in inf['ips']):
                    count += 1
            if count >= 2:
                return 'router'
        return 'host'

    def _node_entry(self, node, ntype, nd, ns, rates):
        ifaces, addrs = [], []
        nd_ifs = (nd or {}).get('ifaces') or {}
        names = [i for i in node.intfNames() if i != 'lo']
        names += sorted(k for k in nd_ifs if k not in names)
        for ifn in names:
            info = nd_ifs.get(ifn) or {}
            r = rates.get((ns, ifn)) or {}
            ips = [a['cidr'] for a in info.get('ips', [])]
            if not ips:
                intf = getattr(node, 'nameToIntf', {}).get(ifn)
                ip = getattr(intf, 'ip', None) if intf else None
                if ip:
                    plen = getattr(intf, 'prefixLen', None)
                    ips = ['%s/%s' % (ip, plen) if plen else ip]
            up = info.get('up')
            if ns == _SELF_NETNS:
                os_ = _operstate(ifn)
                if os_ is not None:
                    up = os_ in ('up', 'unknown')
            ifaces.append({'name': ifn, 'mac': info.get('mac'), 'up': up,
                           'kind': info.get('kind'), 'vlan': info.get('vlan'),
                           'ips': ips, 'rx_bps': r.get('rx_bps', 0), 'tx_bps': r.get('tx_bps', 0),
                           'rx_drop': r.get('rx_drop', 0), 'tx_drop': r.get('tx_drop', 0)})
            for c in ips:
                fam = 'inet6' if ':' in c else 'inet'
                addrs.append({'ip': c.split('/')[0], 'cidr': c, 'iface': ifn,
                              'fam': fam, 'tunnel': bool(info.get('kind'))})
        return {'type': ntype, 'role': self._role(node, ntype, nd), 'ifaces': ifaces,
                'addrs': addrs, 'note': self.node_notes.get(node.name)}

    def _tunnels(self, slow, host_names):
        found = {}
        snodes, ipmap = slow['nodes'], slow['ipmap']

        def add(a, b, kind, ia=None, ib=None, auto=True, label=None, color=None):
            if a == b:
                return
            key = (min(a, b), max(a, b), kind)
            e = found.get(key)
            if e is None:
                e = found[key] = {'id': 'tun|%s|%s|%s' % key, 'a': key[0], 'b': key[1],
                                  'kind': kind, 'label': label or kind,
                                  'color': color or TUNNEL_COLORS.get(kind, '#db2777'),
                                  'auto': auto, 'ifaces': {}}
            if ia:
                e['ifaces'][a] = ia
            if ib:
                e['ifaces'][b] = ib

        tun_nets = []
        for h in sorted(host_names):
            nd = snodes.get(h)
            if not nd or nd.get('in_root'):
                continue
            for ifn, inf in nd['ifaces'].items():
                kind = inf.get('kind')
                if not kind or not inf.get('up'):
                    continue
                rem = inf.get('remote')
                if rem and rem in ipmap:
                    add(h, ipmap[rem][0], kind, ifn, None)
                for a in inf.get('ips', []):
                    if a.get('peer') and a['peer'] in ipmap:
                        add(h, ipmap[a['peer']][0], kind, ifn, ipmap[a['peer']][1])
                    if a['fam'] == 'inet' and not a['cidr'].endswith('/32'):
                        try:
                            tun_nets.append((h, ifn, kind, ipaddress.ip_interface(a['cidr']).network))
                        except ValueError:
                            pass
            for s, d in nd.get('xfrm', []):
                if s in ipmap and d in ipmap:
                    add(ipmap[s][0], ipmap[d][0], 'IPsec')
            for ifn, ep in nd.get('wg', []):
                if ep in ipmap:
                    add(h, ipmap[ep][0], 'WireGuard', ifn, None)
        for i in range(len(tun_nets)):
            for j in range(i + 1, len(tun_nets)):
                hi, ii, ki, ni = tun_nets[i]
                hj, ij, kj, nj = tun_nets[j]
                if hi != hj and ni == nj:
                    add(hi, hj, ki, ii, ij)
        for t in self.tunnels_manual:
            add(t['a'], t['b'], t['kind'], auto=False, label=t['label'], color=t['color'])
        return sorted(found.values(), key=lambda e: e['id'])

    def _compute_state(self):
        now = time.time()
        slow = self._get_slow()
        topo = self.get_topology()
        snodes, ovs, ipmap = slow['nodes'], slow['ovs'], slow['ipmap']
        hosts = list(self.net.hosts)
        switches = list(self.net.switches)
        host_names = set(h.name for h in hosts)
        sw_names = set(s.name for s in switches)
        first = self._first

        # -- interface counters -> rates
        devs, node_ns = {}, {}
        for n in switches + hosts:
            pid = getattr(n, 'pid', None)
            ns = _netns(pid)
            node_ns[n.name] = ns
            if ns and ns not in devs:
                devs[ns] = _read_netdev(pid)
        rates, newprev = {}, {}
        for ns, dev in devs.items():
            for ifn, c in dev.items():
                key = (ns, ifn)
                p = self._prev_ctr.get(key)
                r = {'rx_bps': 0.0, 'tx_bps': 0.0, 'rx_pps': 0.0, 'tx_pps': 0.0,
                     'rx_drop': c[2], 'tx_drop': c[5]}
                if p and now - p[0] > 0.05:
                    dt = now - p[0]
                    r['rx_bps'] = max(0.0, (c[0] - p[1][0]) * 8.0 / dt)
                    r['tx_bps'] = max(0.0, (c[3] - p[1][3]) * 8.0 / dt)
                    r['rx_pps'] = max(0.0, (c[1] - p[1][1]) / dt)
                    r['tx_pps'] = max(0.0, (c[4] - p[1][4]) / dt)
                rates[key] = r
                newprev[key] = (now, c)
        self._prev_ctr = newprev

        # -- per-host sockets/firewall and per-switch flow tables (parallel)
        jobs = []
        for h in hosts:
            if node_ns.get(h.name) and node_ns[h.name] != _SELF_NETNS:
                jobs.append(('host', h))
        if _OVS_OFCTL:
            for s in switches:
                if _is_ovs(s):
                    jobs.append(('sw', s))

        def work(job):
            kind, n = job
            if kind == 'host':
                return n.name, _sh(n.pid, FAST_HOST_SCRIPT, 4)
            return n.name, _run([_OVS_OFCTL, '-O', OF_PROTOS, 'dump-flows', n.name], 3)

        results = dict(self._pool.map(work, jobs)) if jobs else {}

        nodes_out, conns_raw, listen = {}, [], {}
        for c in self.net.controllers:
            nodes_out[c.name] = {'type': 'controller', 'role': 'controller', 'ifaces': [],
                                 'addrs': [], 'note': self.node_notes.get(c.name),
                                 'drops': 0, 'dropDelta': 0, 'aclRules': 0}
        for h in hosts:
            nd = snodes.get(h.name)
            entry = self._node_entry(h, 'host', nd, node_ns.get(h.name), rates)
            drops = rules = 0
            lst, seen = [], set()
            raw = results.get(h.name)
            if raw:
                sec = _sections(raw, ('CONN', 'LISTEN', 'IPT'))
                for c in _parse_ss(sec['CONN']):
                    if c['state'] in ('LISTEN', 'UNCONN'):
                        continue
                    c['host'] = h.name
                    conns_raw.append(c)
                for c in _parse_ss(sec['LISTEN']):
                    k = (c['proto'], c['lport'], c['proc'])
                    if k not in seen:
                        seen.add(k)
                        lst.append({'proto': c['proto'], 'port': c['lport'], 'proc': c['proc']})
                drops, rules = _parse_ipt(sec['IPT'])
            lst.sort(key=lambda x: (x['proto'], x['port']))
            listen[h.name] = set((l['proto'], l['port']) for l in lst)
            entry.update({'listen': lst, 'drops': drops, 'aclRules': rules})
            nodes_out[h.name] = entry
        for s in switches:
            entry = self._node_entry(s, 'switch', snodes.get(s.name), node_ns.get(s.name), rates)
            total, drules, dpk = _parse_flows(results.get(s.name, '') or '')
            entry.update({'flows': total, 'drops': dpk, 'aclRules': drules,
                          'dpid': getattr(s, 'dpid', None), 'listen': []})
            for i in entry['ifaces']:
                i['vlanPort'] = _port_desc(ovs.get(i['name']))
            nodes_out[s.name] = entry

        # drop counter deltas -> events
        for name, e in nodes_out.items():
            prev = self._prev_drops.get(name)
            d = e.get('drops', 0)
            e['dropDelta'] = max(0, d - prev) if prev is not None else 0
            self._prev_drops[name] = d
            if e['dropDelta'] and not first:
                what = 'flow rules' if e['type'] == 'switch' else 'iptables'
                self._event('%s: %d packet(s) dropped by %s' % (name, e['dropDelta'], what), 'warn')

        # -- links
        links_out = {}
        for L in topo['links']:
            ups = []
            for nn, ifn in ((L['a'], L['ia']), (L['b'], L['ib'])):
                ns = node_ns.get(nn)
                if ns is None:
                    continue
                if ns == _SELF_NETNS:
                    os_ = _operstate(ifn)
                    if os_ is not None:
                        ups.append(os_ in ('up', 'unknown'))
                        continue
                nd = snodes.get(nn)
                inf = nd['ifaces'].get(ifn) if nd else None
                if inf is not None:
                    ups.append(bool(inf['up']))
            up = all(ups) if ups else True
            ra = rates.get((node_ns.get(L['a']), L['ia'])) or \
                rates.get((node_ns.get(L['b']), L['ib'])) or {}
            pa, pb = ovs.get(L['ia']), ovs.get(L['ib'])
            carries = _intersect(_port_allows(pa), _port_allows(pb))
            links_out[L['id']] = {
                'up': up,
                'bps': ra.get('rx_bps', 0) + ra.get('tx_bps', 0),
                'pps': ra.get('rx_pps', 0) + ra.get('tx_pps', 0),
                'carries': sorted(carries) if carries is not None else None,
                'portA': _port_desc(pa), 'portB': _port_desc(pb),
                'note': self.link_notes.get(tuple(sorted((L['a'], L['b'])))),
            }
            prev = self._prev_link_up.get(L['id'])
            if prev is not None and prev != up:
                self._event('Link %s - %s is %s' % (L['a'], L['b'], 'UP' if up else 'DOWN'),
                            'ok' if up else 'error')
            self._prev_link_up[L['id']] = up

        # -- groups
        vlan_members = defaultdict(set)
        access_sw = defaultdict(list)
        for L in topo['links']:
            for h, s, si in ((L['a'], L['b'], L['ib']), (L['b'], L['a'], L['ia'])):
                if h in host_names and s in sw_names:
                    access_sw[h].append((s, L['id']))
                    p = ovs.get(si)
                    if p and p['tag'] is not None and not p['trunks']:
                        vlan_members[p['tag']].add(h)
        for h in hosts:
            for i in nodes_out[h.name]['ifaces']:
                if i.get('vlan') is not None:
                    vlan_members[i['vlan']].add(h.name)
        subnet_members = defaultdict(set)
        for h in hosts:
            for a in nodes_out[h.name]['addrs']:
                if a['fam'] != 'inet' or a['tunnel'] or a['cidr'].endswith('/32') or '/' not in a['cidr']:
                    continue
                try:
                    subnet_members[str(ipaddress.ip_interface(a['cidr']).network)].add(h.name)
                except ValueError:
                    pass
        groups = {'vlan': {}, 'subnet': {}, 'custom': {}}
        for i, vid in enumerate(sorted(vlan_members)):
            groups['vlan']['VLAN %d' % vid] = {'members': sorted(vlan_members[vid]), 'vid': vid,
                                               'color': GROUP_PALETTE[i % len(GROUP_PALETTE)]}
        for i, net in enumerate(sorted(subnet_members, key=lambda s: ipaddress.ip_network(s))):
            groups['subnet'][net] = {'members': sorted(subnet_members[net]),
                                     'color': GROUP_PALETTE[i % len(GROUP_PALETTE)]}
        for i, g in enumerate(self.custom_groups):
            groups['custom'][g['name']] = {'members': list(g['members']),
                                           'color': g['color'] or GROUP_PALETTE[i % len(GROUP_PALETTE)]}

        # -- warnings
        warnings = []
        for L in topo['links']:
            if not links_out[L['id']]['up']:
                warnings.append({'level': 'error', 'text': 'Link %s - %s is down' % (L['a'], L['b']),
                                 'links': [L['id']]})
        vlans_present = bool(vlan_members) or any(p['tag'] is not None or p['trunks'] for p in ovs.values())
        if vlans_present:
            sw_adj = defaultdict(list)
            for L in topo['links']:
                if L['a'] in sw_names and L['b'] in sw_names:
                    sw_adj[L['a']].append((L['b'], L['id']))
                    sw_adj[L['b']].append((L['a'], L['id']))
                    aa = _port_allows(ovs.get(L['ia']))
                    ab = _port_allows(ovs.get(L['ib']))
                    if aa != ab:
                        def fmt(x):
                            return 'all VLANs' if x is None else ('VLAN ' + ','.join(str(v) for v in sorted(x)) if x else 'no VLANs')
                        warnings.append({'level': 'info', 'links': [L['id']], 'text':
                                         'Trunk mismatch %s - %s: %s allows %s, %s allows %s (only the overlap is carried)'
                                         % (L['a'], L['b'], L['ia'], fmt(aa), L['ib'], fmt(ab))})
            for vid in sorted(vlan_members):
                def carries_v(lid, vid=vid):
                    lo = links_out[lid]
                    return lo['up'] and (lo['carries'] is None or vid in lo['carries'])
                comp = {}
                for start in sorted(sw_names):
                    if start in comp:
                        continue
                    comp[start] = start
                    q = [start]
                    while q:
                        u = q.pop()
                        for v, lid in sw_adj[u]:
                            if v not in comp and carries_v(lid):
                                comp[v] = start
                                q.append(v)
                segs = defaultdict(list)
                for h in sorted(vlan_members[vid]):
                    attached = [s for s, lid in access_sw[h] if carries_v(lid)]
                    segs[comp.get(attached[0], attached[0]) if attached else ('x', h)].append(h)
                if len(segs) > 1:
                    blocked = []
                    for L in topo['links']:
                        if L['a'] in sw_names and L['b'] in sw_names and not carries_v(L['id']):
                            blocked.append(L['id'])
                    warnings.append({'level': 'warn', 'links': blocked, 'text':
                                     'VLAN %d is split at Layer 2: %s cannot reach each other (check trunks / link state)'
                                     % (vid, ' | '.join('{' + ', '.join(m) + '}' for m in segs.values()))})
        for h in hosts:
            if not nodes_out[h.name]['addrs']:
                warnings.append({'level': 'info', 'text': '%s has no IP address' % h.name, 'links': []})

        # -- tunnels
        tunnels = self._tunnels(slow, host_names)
        tkeys = set(t['id'] for t in tunnels)
        if not first:
            for t in tunnels:
                if t['id'] not in self._prev_tunnels:
                    self._event('Tunnel detected: %s %s <-> %s' % (t['label'], t['a'], t['b']), 'ok')
            for tid in self._prev_tunnels - tkeys:
                p = tid.split('|')
                self._event('Tunnel gone: %s %s <-> %s' % (p[3], p[1], p[2]), 'warn')
        self._prev_tunnels = tkeys
        pair_tunnel = {}
        for t in tunnels:
            pair_tunnel.setdefault((t['a'], t['b']), t)
            pair_tunnel.setdefault((t['b'], t['a']), t)
        ip_iface = {}
        for name, e in nodes_out.items():
            for a in e.get('addrs', []):
                ip_iface[(name, a['ip'])] = a

        # -- connections
        conns = {}
        for c in conns_raw:
            if c['lip'].startswith('127.') or c['lip'] in ('::1', '*'):
                continue
            a = c['host']
            peer = ipmap.get(c['pip'])
            b = peer[0] if peer else 'ext:' + c['pip']
            ea, eb = (a, c['lip'], c['lport']), (b, c['pip'], c['pport'])
            key = (c['proto'],) + tuple(sorted([ea, eb]))
            ent = conns.setdefault(key, {'procs': {}})
            if c['proc']:
                ent['procs'][ea] = c['proc']
        conn_list, conn_keys = [], set()
        for key, ent in conns.items():
            proto, e1, e2 = key
            def is_server(e):
                return (proto, e[2]) in listen.get(e[0], set())
            if is_server(e1) and not is_server(e2):
                srv, cli = e1, e2
            elif is_server(e2) and not is_server(e1):
                srv, cli = e2, e1
            else:
                srv, cli = (e1, e2) if e1[2] <= e2[2] else (e2, e1)
            cls = self._classify(proto, e1[2], e2[2])
            tun = None
            for host, ip in ((cli[0], cli[1]), (srv[0], srv[1])):
                ai = ip_iface.get((host, ip))
                if ai and ai['tunnel']:
                    t = pair_tunnel.get((cli[0], srv[0]))
                    if t:
                        tun = t['id']
                    break
            if tun is None:
                t = pair_tunnel.get((cli[0], srv[0]))
                if t and t['kind'] == 'IPsec':
                    tun = t['id']
            cid = '%s %s:%s:%s %s:%s:%s' % ((proto,) + cli + srv)
            conn_keys.add(cid)
            conn_list.append({
                'id': cid, 'proto': proto, 'cls': cls['name'], 'color': cls['color'],
                'a': cli[0], 'aip': cli[1], 'aport': cli[2],
                'b': srv[0], 'bip': srv[1], 'bport': srv[2],
                'cproc': ent['procs'].get(cli, ''), 'sproc': ent['procs'].get(srv, ''),
                'tunnel': tun, 'ext': cli[0].startswith('ext:') or srv[0].startswith('ext:'),
            })
        conn_list.sort(key=lambda c: (c['cls'], c['a'], c['b'], c['bport']))
        if not first:
            new = [c for c in conn_list if c['id'] not in self._prev_conns]
            for c in new[:8]:
                self._event('New %s flow (%s): %s:%s -> %s:%s%s' % (
                    c['proto'].upper(), c['cls'], c['a'], c['aport'], c['b'], c['bport'],
                    ' [%s]' % (c['sproc'] or c['cproc']) if (c['sproc'] or c['cproc']) else ''))
            if len(new) > 8:
                self._event('... and %d more new flows' % (len(new) - 8))
        self._prev_conns = conn_keys
        self._first = False

        classes = [{'name': c['name'], 'color': c['color']} for c in self._classes()]
        classes += [{'name': OTHER_TCP['name'], 'color': OTHER_TCP['color']},
                    {'name': OTHER_UDP['name'], 'color': OTHER_UDP['color']}]
        dedup, seen = [], set()
        for c in classes:
            if c['name'] not in seen:
                seen.add(c['name'])
                dedup.append(c)

        return {'t': now, 'sig': topo['sig'], 'nodes': nodes_out, 'links': links_out,
                'groups': groups, 'tunnels': tunnels, 'connections': conn_list[:300],
                'classes': dedup, 'warnings': warnings, 'vlans': vlans_present}

    # ---- on-demand details --------------------------------------------------

    def node_details(self, name):
        node = self._node_by_name(name)
        if node is None:
            raise ValueError('unknown node %r' % name)
        sections = []
        if node in self.net.controllers:
            sections.append(('Controller', 'Class: %s\nAddress: %s\nPort: %s' % (
                type(node).__name__, getattr(node, 'ip', '?'), getattr(node, 'port', '?'))))
            sections.append(('Switches managed', '\n'.join(s.name for s in self.net.switches)))
        elif node in self.net.switches:
            q = shlex.quote(node.name)
            if _is_ovs(node) and _OVS_OFCTL:
                script = (
                    'echo "@@OpenFlow flow table"; ovs-ofctl -O %(p)s dump-flows %(q)s 2>&1; '
                    'echo "@@Port statistics"; ovs-ofctl -O %(p)s dump-ports %(q)s 2>&1; '
                    'echo "@@MAC learning table"; ovs-appctl fdb/show %(q)s 2>&1; '
                    'echo "@@Ports and VLAN config"; for p in $(ovs-vsctl list-ports %(q)s); do '
                    'echo "$p  tag=$(ovs-vsctl get port $p tag) trunks=$(ovs-vsctl get port $p trunks) '
                    'mode=$(ovs-vsctl get port $p vlan_mode)"; done; '
                    'echo "@@Controller / fail mode"; ovs-vsctl get-controller %(q)s; '
                    'echo "fail-mode: $(ovs-vsctl get-fail-mode %(q)s)"; '
                    'echo "protocols: $(ovs-vsctl get bridge %(q)s protocols)"; '
                    'echo "datapath_id: $(ovs-vsctl get bridge %(q)s datapath_id)"'
                ) % {'p': OF_PROTOS, 'q': q}
            else:
                script = ('echo "@@Bridge"; bridge link show 2>/dev/null; '
                          'echo "@@Forwarding database"; bridge fdb show br %(q)s 2>/dev/null; '
                          'echo "@@VLANs"; bridge vlan show 2>/dev/null' % {'q': q})
            sections = _sections_ordered(_sh(node.pid, script, timeout=6))
        else:
            sections = _sections_ordered(_sh(node.pid, HOST_DETAIL_SCRIPT, timeout=6))
        return {'name': name, 'sections': [{'title': t, 'body': b} for t, b in sections]}

    def _host_ipv4s(self, name):
        slow = self._get_slow()
        nd = slow['nodes'].get(name) or {}
        res = []
        for ifn, inf in (nd.get('ifaces') or {}).items():
            for a in inf['ips']:
                if a['fam'] == 'inet':
                    res.append((a['ip'], ifn, bool(inf.get('kind'))))
        if not res:
            h = self._node_by_name(name)
            try:
                if h is not None and h.IP():
                    res.append((h.IP(), h.defaultIntf().name, False))
            except Exception:
                pass
        res.sort(key=lambda x: (x[2], x[1]))   # physical interfaces first
        return res

    def do_ping(self, src, dst, ip=None, count=3):
        hosts = dict((h.name, h) for h in self.net.hosts)
        if src not in hosts or dst not in hosts or src == dst:
            raise ValueError('choose two different hosts')
        ips = self._host_ipv4s(dst)
        if not ips:
            raise ValueError('%s has no IPv4 address' % dst)
        if ip:
            match = [x for x in ips if x[0] == ip]
            if not match:
                raise ValueError('%s is not an address of %s' % (ip, dst))
            target = match[0]
        else:
            target = ips[0]
        count = max(1, min(int(count or 3), 10))
        prefix = _ns_prefix(hosts[src].pid)
        if prefix is None:
            raise ValueError('cannot enter namespace of %s' % src)
        cmd = ['ping', '-c', str(count), '-W', '1', '-i', '0.3' if count > 1 else '1', target[0]]
        out = _run(prefix + cmd, timeout=count * 1.5 + 3)
        m = re.search(r'(\d+) (?:packets )?received', out)
        received = int(m.group(1)) if m else 0
        rtt = re.search(r'= [\d.]+/([\d.]+)/', out)
        ok = received > 0
        tunnel = None
        if target[2]:
            for t in self.get_state().get('tunnels', []):
                if set((t['a'], t['b'])) == set((src, dst)):
                    tunnel = t['id']
                    break
        self._event('ping %s -> %s (%s): %s' % (
            src, dst, target[0],
            ('%d/%d replies, avg %s ms' % (received, count, rtt.group(1) if rtt else '?')) if ok else 'FAILED'),
            'ok' if ok else 'error')
        return {'ok': ok, 'received': received, 'count': count, 'ip': target[0],
                'output': out.strip() or '(no output - is ping installed?)', 'tunnel': tunnel}

    def do_matrix(self):
        hosts = list(self.net.hosts)[:30]
        targets = {}
        for h in hosts:
            ips = self._host_ipv4s(h.name)
            targets[h.name] = ips[0][0] if ips else None
        prefixes = dict((h.name, _ns_prefix(h.pid)) for h in hosts)
        pairs = [(a.name, b.name) for a in hosts for b in hosts
                 if a.name != b.name and targets[b.name] and prefixes[a.name] is not None]

        def one(pair):
            a, b = pair
            out = _run(prefixes[a] + ['ping', '-c', '1', '-W', '1', targets[b]], timeout=3)
            m = re.search(r'(\d+) (?:packets )?received', out)
            return pair, bool(m and int(m.group(1)) > 0)

        matrix = dict((h.name, {}) for h in hosts)
        with ThreadPoolExecutor(max_workers=16) as ex:
            for (a, b), ok in ex.map(one, pairs):
                matrix[a][b] = ok
        okc = sum(1 for a in matrix for b in matrix[a] if matrix[a][b])
        self._event('Reachability matrix: %d/%d host pairs reachable' % (okc, len(pairs)),
                    'ok' if okc == len(pairs) else 'warn')
        return {'hosts': [h.name for h in hosts], 'targets': targets, 'matrix': matrix,
                'reachable': okc, 'total': len(pairs)}

    # ---- web server ------------------------------------------------------------

    def start(self):
        handler = _make_handler(self)
        self.httpd = _Server((self.bind, self.port), handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       name='mnviz-%d' % self.port)
        self.thread.daemon = True
        self.thread.visualizer = self
        self.thread.start()
        local = self.bind in ('127.0.0.1', 'localhost')
        print('\n' + '=' * 70)
        print('Mininet Network Visualizer started')
        print('=' * 70)
        print('\n   Open in browser: http://localhost:%d' % self.port)
        if local:
            print('   (listening on 127.0.0.1 only - from another machine use')
            print('    ssh -L %d:localhost:%d <user>@<this-vm>, or set MNVIZ_BIND=0.0.0.0)' %
                  (self.port, self.port))
        else:
            print('   (listening on %s - reachable at http://<vm-ip>:%d)' %
                  (self.bind or '0.0.0.0', self.port))
        print('\n' + '=' * 70 + '\n')
        return self.thread

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None
        self._pool.shutdown(wait=False)

    # Backwards compatibility: original API name
    def start_server(self):
        self.start()
        self.thread.join()


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(viz):
    local_names = ('localhost', '127.0.0.1', '[::1]', '')

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = 'MNViz/2'

        def log_message(self, *args):
            pass

        def _host_ok(self):
            if viz.bind not in ('127.0.0.1', 'localhost'):
                return True
            h = (self.headers.get('Host') or '').lower()
            hn = h.split(']')[0] + ']' if h.startswith('[') else h.rsplit(':', 1)[0]
            return hn in local_names

        def _send(self, code, body, ctype='application/json; charset=utf-8'):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            try:
                self.send_response(code)
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {'error': 'forbidden host header'})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            try:
                if u.path in ('/', '/index.html'):
                    return self._send(200, HTML_PAGE, 'text/html; charset=utf-8')
                if u.path in ('/api/topology', '/topology.json'):
                    return self._send(200, viz.get_topology())
                if u.path == '/api/state':
                    since = int((q.get('since') or ['0'])[0] or 0)
                    return self._send(200, viz.get_state(since))
                if u.path == '/api/node':
                    return self._send(200, viz.node_details((q.get('name') or [''])[0]))
                return self._send(404, {'error': 'not found'})
            except ValueError as e:
                return self._send(400, {'error': str(e)})
            except Exception as e:
                traceback.print_exc()
                return self._send(500, {'error': '%s: %s' % (type(e).__name__, e)})

        def do_POST(self):
            if not self._host_ok() or self.headers.get('X-MNViz') != '1':
                return self._send(403, {'error': 'forbidden'})
            try:
                n = int(self.headers.get('Content-Length') or 0)
                if n > 65536:
                    return self._send(413, {'error': 'request too large'})
                body = json.loads(self.rfile.read(n) or b'{}')
                if self.path == '/api/ping':
                    return self._send(200, viz.do_ping(body.get('src'), body.get('dst'),
                                                       body.get('ip'), body.get('count', 3)))
                if self.path == '/api/matrix':
                    return self._send(200, viz.do_matrix())
                return self._send(404, {'error': 'not found'})
            except ValueError as e:
                return self._send(400, {'error': str(e)})
            except Exception as e:
                traceback.print_exc()
                return self._send(500, {'error': '%s: %s' % (type(e).__name__, e)})

    return Handler


# ---------------------------------------------------------------------------
# Module-level API
# ---------------------------------------------------------------------------

_REGISTRY = {}
_REG_LOCK = threading.Lock()


def start_visualizer(net, port=9090, host=None):
    """
    Start the visualizer for a Mininet network.

    Args:
        net:  Mininet network object (after net.start())
        port: web server port (default 9090)
        host: address to listen on (default 127.0.0.1, or $MNVIZ_BIND)

    Returns:
        The server thread; thread.visualizer is the MininetVisualizer.
        Calling this again for the same network returns the running instance.
    """
    with _REG_LOCK:
        existing = _REGISTRY.get(int(port))
        if existing is not None:
            if existing.net is net:
                print('*** Visualizer already running on port %d' % int(port))
                return existing.thread
            existing.stop()
            del _REGISTRY[int(port)]
        viz = MininetVisualizer(net, port, host)
        thread = viz.start()
        _REGISTRY[int(port)] = viz
        return thread


def get_visualizer(port=None):
    """Return the running visualizer (for annotations), or None."""
    with _REG_LOCK:
        if port is not None:
            return _REGISTRY.get(int(port))
        return next(iter(_REGISTRY.values()), None)


def stop_visualizer(port=None):
    with _REG_LOCK:
        ports = [int(port)] if port is not None else list(_REGISTRY)
        for p in ports:
            v = _REGISTRY.pop(p, None)
            if v:
                v.stop()


# ---------------------------------------------------------------------------
# Web page
# ---------------------------------------------------------------------------

HTML_PAGE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mininet Visualizer</title>
<style>
:root{
  --bg:#eef1f7; --panel:#ffffff; --panel2:#f5f7fb; --text:#1e293b; --muted:#64748b;
  --border:#dbe2ea; --accent:#4f46e5; --accent-text:#ffffff;
  --c-canvas:#ffffff; --c-grid:#eef2f7; --c-text:#1e293b; --c-muted:#64748b;
  --c-link:#a3b1c4; --c-linkActive:#4f46e5; --c-labelBg:rgba(255,255,255,.9);
  --c-host:#22c55e; --c-switch:#3b82f6; --c-router:#f59e0b; --c-controller:#8b5cf6;
  --c-firewall:#be123c; --c-danger:#ef4444; --c-ok:#16a34a; --c-accent:#4f46e5; --c-border:#cbd5e1;
  --ok:#16a34a; --warn:#d97706; --err:#dc2626; --info:#2563eb;
}
@media (prefers-color-scheme: dark){
  :root:not([data-theme="light"]){
    --bg:#0b1020; --panel:#121a2b; --panel2:#18223a; --text:#e2e8f0; --muted:#94a3b8;
    --border:#26324a; --accent:#818cf8; --accent-text:#0b1020;
    --c-canvas:#0f172a; --c-grid:#152038; --c-text:#e2e8f0; --c-muted:#94a3b8;
    --c-link:#55657f; --c-linkActive:#a5b4fc; --c-labelBg:rgba(15,23,42,.9);
    --c-host:#22c55e; --c-switch:#3b82f6; --c-router:#f59e0b; --c-controller:#a78bfa;
    --c-firewall:#f43f5e; --c-danger:#f87171; --c-ok:#4ade80; --c-accent:#818cf8; --c-border:#334155;
    --ok:#4ade80; --warn:#fbbf24; --err:#f87171; --info:#60a5fa;
  }
}
:root[data-theme="dark"]{
  --bg:#0b1020; --panel:#121a2b; --panel2:#18223a; --text:#e2e8f0; --muted:#94a3b8;
  --border:#26324a; --accent:#818cf8; --accent-text:#0b1020;
  --c-canvas:#0f172a; --c-grid:#152038; --c-text:#e2e8f0; --c-muted:#94a3b8;
  --c-link:#55657f; --c-linkActive:#a5b4fc; --c-labelBg:rgba(15,23,42,.9);
  --c-host:#22c55e; --c-switch:#3b82f6; --c-router:#f59e0b; --c-controller:#a78bfa;
  --c-firewall:#f43f5e; --c-danger:#f87171; --c-ok:#4ade80; --c-accent:#818cf8; --c-border:#334155;
  --ok:#4ade80; --warn:#fbbf24; --err:#f87171; --info:#60a5fa;
}
*{box-sizing:border-box}
html,body{margin:0;height:100%}
body{background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,Ubuntu,sans-serif;display:flex;flex-direction:column;min-height:100vh}
header{display:flex;flex-wrap:wrap;align-items:center;gap:10px 16px;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:10px;margin-right:auto}
.brand b{font-size:16px}
.pill{font-size:12px;padding:2px 8px;border-radius:999px;background:var(--panel2);color:var(--muted);border:1px solid var(--border)}
.pill.ok{color:var(--ok)} .pill.bad{color:var(--err)}
.toolbar{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center}
.grp{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
button,select,input{font:inherit;color:inherit}
button{background:var(--panel2);border:1px solid var(--border);border-radius:7px;padding:5px 10px;cursor:pointer}
button:hover{border-color:var(--accent)}
button.primary{background:var(--accent);color:var(--accent-text);border-color:var(--accent);font-weight:600}
button:disabled{opacity:.55;cursor:wait}
select,input[type=number]{background:var(--panel2);border:1px solid var(--border);border-radius:7px;padding:4px 6px}
label{display:inline-flex;align-items:center;gap:5px;cursor:pointer;user-select:none}
.toggles label{font-size:13px;padding:3px 6px;border-radius:6px;background:var(--panel2);border:1px solid var(--border)}
#legend{display:flex;flex-wrap:wrap;gap:6px 14px;align-items:center;padding:7px 16px;background:var(--panel);border-bottom:1px solid var(--border);font-size:12.5px;min-height:34px}
#legend .lg-title{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.04em}
.chip{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:999px;border:1px solid var(--border);background:var(--panel2);cursor:pointer;font-size:12.5px}
.chip.focus{outline:2px solid var(--accent)}
.chip.static{cursor:default}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;flex:none}
.sq{width:12px;height:4px;border-radius:2px;display:inline-block;flex:none}
main{flex:1;display:flex;min-height:0}
#stage{flex:1;position:relative;min-width:0;min-height:420px}
#cv{position:absolute;inset:0;display:block;touch-action:none;cursor:grab}
#cv.dragging{cursor:grabbing}
#hint{position:absolute;left:12px;bottom:10px;font-size:12px;color:var(--muted);background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:4px 8px;opacity:.92;pointer-events:none}
#tooltip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:7px 9px;font-size:12.5px;box-shadow:0 6px 18px rgba(0,0,0,.18);display:none;max-width:320px;z-index:5}
#pickbar{position:absolute;top:10px;left:50%;transform:translateX(-50%);background:var(--accent);color:var(--accent-text);padding:5px 12px;border-radius:999px;font-size:13px;display:none}
aside{width:380px;flex:none;background:var(--panel);border-left:1px solid var(--border);display:flex;flex-direction:column;min-height:0}
.tabs{display:flex;border-bottom:1px solid var(--border)}
.tabs button{flex:1;border:0;border-radius:0;background:transparent;padding:9px 4px;border-bottom:2px solid transparent;color:var(--muted);font-weight:600}
.tabs button.active{color:var(--text);border-bottom-color:var(--accent)}
.badge{display:inline-block;min-width:18px;padding:0 5px;margin-left:5px;border-radius:999px;background:var(--err);color:#fff;font-size:11px;line-height:17px}
.badge:empty{display:none}
.tab{display:none;overflow:auto;padding:14px;flex:1}
.tab.active{display:block}
h2{font-size:17px;margin:0}
h3{font-size:13px;margin:16px 0 6px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
h3:first-child{margin-top:0}
.dhead{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.tag{font-size:11.5px;padding:1px 7px;border-radius:999px;background:var(--panel2);border:1px solid var(--border);color:var(--muted)}
.note{background:var(--panel2);border-left:3px solid var(--accent);padding:6px 9px;border-radius:4px;margin:6px 0}
.muted{color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:12.5px}
th,td{text-align:left;padding:4px 5px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
td.num{text-align:right;white-space:nowrap}
.up{color:var(--ok)} .down{color:var(--err)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:6px}
.stat{background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:7px;text-align:center}
.stat b{display:block;font-size:18px}
.stat span{font-size:11.5px;color:var(--muted)}
.warn{padding:6px 8px;border-radius:6px;margin:4px 0;font-size:12.5px;border-left:3px solid;background:var(--panel2);cursor:pointer}
.warn.error{border-color:var(--err)} .warn.warn{border-color:var(--warn)} .warn.info{border-color:var(--info)}
details{border:1px solid var(--border);border-radius:7px;margin:6px 0;background:var(--panel2)}
summary{cursor:pointer;padding:6px 9px;font-weight:600;font-size:13px}
pre{margin:0;padding:8px 10px;font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre;overflow:auto;max-height:340px;border-top:1px solid var(--border)}
pre.out{border:1px solid var(--border);border-radius:7px;margin-top:8px;background:var(--panel2);min-height:40px}
.card{border:1px solid var(--border);border-radius:9px;padding:12px;margin-bottom:12px;background:var(--panel)}
.form{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
.form label{flex-direction:column;align-items:stretch;gap:3px;font-size:12px;color:var(--muted)}
.row{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}
.ev{display:flex;gap:8px;padding:5px 0;border-bottom:1px solid var(--border);font-size:12.5px}
.ev time{color:var(--muted);flex:none;font-variant-numeric:tabular-nums}
.ev.error .t{color:var(--err)} .ev.warn .t{color:var(--warn)} .ev.ok .t{color:var(--ok)}
.matrix td,.matrix th{text-align:center;padding:3px;font-size:12px}
.matrix td.y{background:color-mix(in srgb,var(--ok) 25%,transparent);cursor:pointer}
.matrix td.n{background:color-mix(in srgb,var(--err) 25%,transparent);cursor:pointer}
.matrix td.self{background:var(--panel2)}
.conn td{font-size:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.linkbtn{background:none;border:0;padding:0;color:var(--accent);cursor:pointer;text-decoration:underline}
@media (max-width:900px){
  main{flex-direction:column}
  #stage{min-height:60vh}
  aside{width:auto;border-left:0;border-top:1px solid var(--border);max-height:none}
  header{padding:8px 16px}
}
</style>
</head>
<body>
<header>
  <div class="brand"><b>Mininet Visualizer</b><span id="status" class="pill">connecting…</span></div>
  <div class="toolbar">
    <div class="grp">
      <button id="btnTree" title="Hierarchical layout">Tree</button>
      <button id="btnForce" title="Force-directed layout">Force</button>
      <button id="btnFit" title="Fit to screen (F)">Fit</button>
    </div>
    <label>Colour by
      <select id="colorBy">
        <option value="auto">Auto</option><option value="vlan">VLAN</option>
        <option value="subnet">Subnet</option><option value="custom">Custom groups</option>
        <option value="none">Node type</option>
      </select>
    </label>
    <div class="grp toggles">
      <label><input type="checkbox" id="tIntf">Interfaces</label>
      <label><input type="checkbox" id="tTraffic">Traffic</label>
      <label><input type="checkbox" id="tTunnels">Tunnels</label>
      <label><input type="checkbox" id="tControl">Control</label>
      <label><input type="checkbox" id="tRates">Rates</label>
    </div>
    <div class="grp">
      <button id="btnPng">Export PNG</button>
      <button id="btnSave">Save layout</button>
      <button id="btnLoad">Load layout</button>
      <input type="file" id="fileLoad" accept=".json,application/json" hidden>
      <button id="btnTheme">Theme</button>
    </div>
  </div>
</header>
<div id="legend"></div>
<main>
  <div id="stage">
    <canvas id="cv"></canvas>
    <div id="pickbar"></div>
    <div id="tooltip"></div>
    <div id="hint">Drag nodes · scroll to zoom · drag background to pan · Shift+click two hosts to ping</div>
  </div>
  <aside>
    <nav class="tabs">
      <button data-tab="details" class="active">Details<span id="warnBadge" class="badge"></span></button>
      <button data-tab="traffic">Traffic<span id="flowBadge" class="badge" style="background:var(--accent)"></span></button>
      <button data-tab="tests">Tests</button>
      <button data-tab="events">Events<span id="evBadge" class="badge"></span></button>
    </nav>
    <section id="tab-details" class="tab active"><div id="detLive"></div><div id="detDeep"></div></section>
    <section id="tab-traffic" class="tab"></section>
    <section id="tab-tests" class="tab">
      <div class="card">
        <h3>Ping test</h3>
        <div class="form">
          <label>From<select id="pSrc"></select></label>
          <label>To<select id="pDst"></select></label>
          <label>Target address<select id="pIp"></select></label>
          <label>Count<input id="pCount" type="number" min="1" max="10" value="3"></label>
        </div>
        <button id="btnPing" class="primary">Run ping</button>
        <pre id="pingOut" class="out muted">Results appear here. Tip: Shift+click two hosts on the map.</pre>
      </div>
      <div class="card">
        <h3>Reachability matrix</h3>
        <p class="muted" style="margin:0 0 8px">Pings every host from every other host once (1 s timeout). Shows the combined effect of VLANs, ACLs, firewalls, routing and tunnels at a glance. Click a cell to animate that ping.</p>
        <button id="btnMatrix" class="primary">Run matrix</button>
        <div id="matrixOut" style="margin-top:10px;overflow:auto"></div>
      </div>
    </section>
    <section id="tab-events" class="tab">
      <div class="row"><b>Event log</b><button id="btnClearEv">Clear</button></div>
      <div id="evList"></div>
    </section>
  </aside>
</main>
<script>
(function(){
'use strict';
const $ = s => document.querySelector(s);
const $$ = s => Array.from(document.querySelectorAll(s));
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const store = {
  get(k, d){ try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch(e){ return d; } },
  set(k, v){ try { localStorage.setItem(k, JSON.stringify(v)); } catch(e){} }
};
const settings = Object.assign({colorBy:'auto', intf:false, traffic:true, tunnels:true, control:true, rates:true, theme:'auto'}, store.get('mnviz-settings', {}));
const saveSettings = () => store.set('mnviz-settings', settings);

// ------------------------------------------------------------ state
const cv = $('#cv'), ctx = cv.getContext('2d'), stage = $('#stage');
let W = 0, H = 0, DPR = 1;
let topo = {nodes:[], links:[], sig:null}, nodeById = {}, linkById = {}, adj = {};
let live = null, lastSeq = 0, events = [], unseenEv = 0;
let pos = {}, view = {x:0, y:0, k:1};
let sel = null, hover = null, focusGroup = null;
let pingPick = [], anims = [], flashes = {}, warnFlash = null;
let force = null, drag = null, pathCache = {}, memberIdx = {};
let tunnelGeom = {}, deep = null, lastMatrix = null;
let C = {};

// ------------------------------------------------------------ utils
async function api(path, body){
  const opt = body === undefined ? {cache:'no-store'} :
    {method:'POST', headers:{'Content-Type':'application/json', 'X-MNViz':'1'}, body:JSON.stringify(body)};
  const r = await fetch(path, opt);
  let data = null;
  try { data = await r.json(); } catch(e) {}
  if (!r.ok) throw new Error((data && data.error) || ('HTTP ' + r.status));
  return data;
}
function fmtRate(b){
  if (!b || b < 1) return '0 b/s';
  if (b < 1e3) return b.toFixed(0) + ' b/s';
  if (b < 1e6) return (b/1e3).toFixed(1) + ' kb/s';
  if (b < 1e9) return (b/1e6).toFixed(2) + ' Mb/s';
  return (b/1e9).toFixed(2) + ' Gb/s';
}
const fmtTime = t => new Date(t*1000).toLocaleTimeString();
const natural = (a, b) => String(a).localeCompare(String(b), undefined, {numeric:true});
function readColors(){
  const cs = getComputedStyle(document.documentElement);
  for (const k of ['canvas','grid','text','muted','link','linkActive','labelBg','host','switch','router','controller','firewall','danger','ok','accent','border'])
    C[k] = cs.getPropertyValue('--c-' + k).trim();
}
function applyTheme(){
  const r = document.documentElement;
  if (settings.theme === 'auto') r.removeAttribute('data-theme'); else r.setAttribute('data-theme', settings.theme);
  $('#btnTheme').textContent = 'Theme: ' + settings.theme;
  readColors();
}
try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', readColors); } catch(e) {}

// ------------------------------------------------------------ canvas size
function resize(){
  const r = stage.getBoundingClientRect();
  const first = !W;
  DPR = window.devicePixelRatio || 1; W = r.width; H = r.height;
  cv.width = Math.max(1, Math.round(W*DPR)); cv.height = Math.max(1, Math.round(H*DPR));
  if (first && topo.nodes.length) fitView();
}
new ResizeObserver(resize).observe(stage);

// ------------------------------------------------------------ topology
function buildAdj(){
  adj = {};
  topo.nodes.forEach(n => adj[n.id] = []);
  topo.links.forEach(l => {
    (adj[l.a] = adj[l.a] || []).push({to:l.b, link:l.id});
    (adj[l.b] = adj[l.b] || []).push({to:l.a, link:l.id});
  });
}
const notCtl = id => nodeById[id] && nodeById[id].type !== 'controller';
async function loadTopology(){
  topo = await api('/api/topology');
  nodeById = {}; topo.nodes.forEach(n => nodeById[n.id] = n);
  linkById = {}; topo.links.forEach(l => linkById[l.id] = l);
  buildAdj(); pathCache = {};
  const saved = store.get('mnviz-layout-' + topo.sig, null);
  if (saved && saved.positions && topo.nodes.every(n => saved.positions[n.id])) pos = saved.positions;
  else treeLayout();
  fitView();
  populateHostSelects();
}
function bfsDist(src){
  const d = {[src]:0}, q = [src];
  while (q.length){ const u = q.shift(); for (const e of adj[u] || []) if (d[e.to] === undefined && notCtl(e.to)){ d[e.to] = d[u] + 1; q.push(e.to); } }
  return d;
}
function rank(id){ const n = nodeById[id]; const role = nodeRole(n); return n.type === 'switch' ? 0 : (role === 'host' ? 2 : 1); }
function treeLayout(){
  const ids = topo.nodes.filter(n => n.type !== 'controller').map(n => n.id).sort(natural);
  const seen = new Set(), comps = [];
  for (const id of ids){
    if (seen.has(id)) continue;
    const comp = [], q = [id]; seen.add(id);
    while (q.length){ const u = q.shift(); comp.push(u); for (const e of adj[u] || []) if (!seen.has(e.to) && notCtl(e.to)){ seen.add(e.to); q.push(e.to); } }
    comps.push(comp);
  }
  comps.sort((a, b) => b.length - a.length);
  const UNIT = 88, LEVEL = 125;
  let cursor = 0; pos = {};
  for (const comp of comps){
    const sw = comp.filter(id => nodeById[id].type === 'switch');
    const pool = sw.length ? sw : comp;
    let best = pool[0], bestE = Infinity, bestD = -1;
    for (const c of pool){
      const d = bfsDist(c); const ecc = Math.max(...Object.values(d)); const deg = (adj[c] || []).length;
      if (ecc < bestE || (ecc === bestE && deg > bestD)){ best = c; bestE = ecc; bestD = deg; }
    }
    const children = {}, depth = {[best]:0}, vis = new Set([best]), q = [best];
    while (q.length){
      const u = q.shift(); children[u] = [];
      const nb = (adj[u] || []).map(e => e.to).filter(v => notCtl(v));
      nb.sort((a, b) => rank(a) - rank(b) || natural(a, b));
      for (const v of nb){ if (vis.has(v)) continue; vis.add(v); depth[v] = depth[u] + 1; children[u].push(v); q.push(v); }
    }
    const width = {};
    const calc = u => (width[u] = children[u].length ? children[u].reduce((s, v) => s + calc(v), 0) : 1);
    calc(best);
    const place = (u, x0) => { pos[u] = {x:(x0 + width[u]/2)*UNIT, y:depth[u]*LEVEL}; let x = x0; for (const v of children[u]){ place(v, x); x += width[v]; } };
    place(best, cursor);
    cursor += width[best] + 1;
  }
  const ctls = topo.nodes.filter(n => n.type === 'controller');
  const total = Math.max(1, cursor - 1) * UNIT;
  ctls.forEach((n, i) => pos[n.id] = {x: total*(i+1)/(ctls.length+1), y: -LEVEL});
}
function fitView(){
  const ps = Object.values(pos);
  if (!ps.length || !W) return;
  let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
  for (const p of ps){ x0 = Math.min(x0, p.x); y0 = Math.min(y0, p.y); x1 = Math.max(x1, p.x); y1 = Math.max(y1, p.y); }
  const m = 80, bw = x1 - x0 + 2*m, bh = y1 - y0 + 2*m + 30;
  view.k = Math.min(W/bw, H/bh, 1.7);
  view.x = W/2 - (x0 + x1)/2*view.k;
  view.y = H/2 - (y0 + y1 + 30)/2*view.k;
}
function saveLayout(){ if (topo.sig) store.set('mnviz-layout-' + topo.sig, {positions:pos}); }
function startForce(){ force = {iter:0, max:420}; }
function stepForce(){
  const ns = topo.nodes.filter(n => pos[n.id]);
  const alpha = 1 - force.iter/force.max;
  const f = {}; ns.forEach(n => f[n.id] = {x:0, y:0});
  for (let i = 0; i < ns.length; i++) for (let j = i+1; j < ns.length; j++){
    const a = pos[ns[i].id], b = pos[ns[j].id];
    let dx = b.x - a.x, dy = b.y - a.y; let d2 = dx*dx + dy*dy;
    if (d2 < 1){ dx = Math.random() - .5; dy = Math.random() - .5; d2 = 1; }
    const d = Math.sqrt(d2), rep = 14000/d2;
    f[ns[i].id].x -= dx/d*rep; f[ns[i].id].y -= dy/d*rep;
    f[ns[j].id].x += dx/d*rep; f[ns[j].id].y += dy/d*rep;
  }
  const spring = (u, v, len, k) => {
    const a = pos[u], b = pos[v]; if (!a || !b) return;
    const dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1, s = (d - len)*k;
    f[u].x += dx/d*s; f[u].y += dy/d*s; f[v].x -= dx/d*s; f[v].y -= dy/d*s;
  };
  topo.links.forEach(l => spring(l.a, l.b, 105, .06));
  topo.nodes.filter(n => n.type === 'controller').forEach(c => topo.nodes.filter(n => n.type === 'switch').forEach(s => spring(c.id, s.id, 220, .004)));
  let cx = 0, cy = 0; ns.forEach(n => { cx += pos[n.id].x; cy += pos[n.id].y; }); cx /= ns.length || 1; cy /= ns.length || 1;
  ns.forEach(n => {
    if (drag && drag.mode === 'node' && drag.id === n.id) return;
    const p = pos[n.id];
    const fx = f[n.id].x + (cx - p.x)*.004, fy = f[n.id].y + (cy - p.y)*.004;
    p.x += Math.max(-25, Math.min(25, fx*alpha)); p.y += Math.max(-25, Math.min(25, fy*alpha));
  });
  if (++force.iter >= force.max){ force = null; saveLayout(); }
}

// ------------------------------------------------------------ groups
function rebuildIndex(){
  memberIdx = {};
  const g = (live && live.groups) || {};
  for (const mode of Object.keys(g)){
    const idx = {};
    for (const [name, info] of Object.entries(g[mode]))
      for (const m of info.members) (idx[m] = idx[m] || []).push({name, color:info.color, vid:info.vid});
    memberIdx[mode] = idx;
  }
}
function colorMode(){
  if (settings.colorBy !== 'auto') return settings.colorBy;
  const g = (live && live.groups) || {};
  if (g.vlan && Object.keys(g.vlan).length) return 'vlan';
  if (g.custom && Object.keys(g.custom).length) return 'custom';
  if (g.subnet && Object.keys(g.subnet).length > 1) return 'subnet';
  return 'none';
}
const groupsOf = (id, mode) => (memberIdx[mode] && memberIdx[mode][id]) || [];
function groupInfo(){ if (!focusGroup || !live) return null; return ((live.groups || {})[focusGroup.mode] || {})[focusGroup.name] || null; }
function nodeInFocus(id){
  const gi = groupInfo(); if (!gi) return true;
  if (gi.members.includes(id)) return true;
  if (focusGroup.mode === 'vlan' && nodeById[id] && nodeById[id].type === 'switch')
    return (adj[id] || []).some(e => { const s = live.links[e.link]; return s && s.carries && s.carries.includes(gi.vid); });
  return false;
}
function linkInFocus(l){
  const gi = groupInfo(); if (!gi) return true;
  const s = live.links[l.id];
  if (focusGroup.mode === 'vlan' && s && s.carries) return s.carries.includes(gi.vid) && nodeInFocus(l.a) && nodeInFocus(l.b);
  return nodeInFocus(l.a) && nodeInFocus(l.b);
}

// ------------------------------------------------------------ node helpers
function nodeRole(n){ const s = live && live.nodes && live.nodes[n.id]; return (s && s.role) || n.type; }
function typeColor(n){
  const r = nodeRole(n);
  if (n.type === 'controller') return C.controller;
  if (n.type === 'switch') return C.switch;
  if (r === 'router' || r === 'nat' || r === 'vpn-gw' || r === 'gateway') return C.router;
  if (r === 'firewall') return C.firewall;
  return C.host;
}
function nodeFill(n){
  const mode = colorMode();
  if (mode !== 'none' && n.type === 'host'){ const g = groupsOf(n.id, mode); if (g.length === 1) return g[0].color; }
  return typeColor(n);
}
function primaryIp(id){
  const s = live && live.nodes[id]; if (!s || !s.addrs) return '';
  const a = s.addrs.find(a => a.fam === 'inet' && !a.tunnel) || s.addrs.find(a => a.fam === 'inet') || s.addrs[0];
  return a ? a.cidr : '';
}
function isTunnelEndpoint(id){ return live && live.tunnels.some(t => t.a === id || t.b === id); }

// ------------------------------------------------------------ geometry
function polyLen(pts){ let L = 0; for (let i = 1; i < pts.length; i++) L += Math.hypot(pts[i].x - pts[i-1].x, pts[i].y - pts[i-1].y); return L; }
function along(pts, f){
  const L = polyLen(pts); let target = f*L;
  for (let i = 1; i < pts.length; i++){
    const a = pts[i-1], b = pts[i], d = Math.hypot(b.x - a.x, b.y - a.y);
    if (target <= d || i === pts.length - 1){ const t = d ? Math.min(1, target/d) : 0; return {x:a.x + (b.x - a.x)*t, y:a.y + (b.y - a.y)*t}; }
    target -= d;
  }
  return pts[pts.length - 1];
}
function bfsPath(a, b){
  const key = a + '>' + b; if (pathCache[key]) return pathCache[key];
  if (!nodeById[a] || !nodeById[b]) return null;
  const prev = {[a]:null}, q = [a];
  while (q.length){
    const u = q.shift(); if (u === b) break;
    for (const e of adj[u] || []){
      if (prev[e.to] !== undefined || !notCtl(e.to)) continue;
      const s = live && live.links[e.link]; if (s && s.up === false) continue;
      prev[e.to] = u; q.push(e.to);
    }
  }
  if (prev[b] === undefined) return (pathCache[key] = null);
  const path = []; for (let u = b; u != null; u = prev[u]) path.unshift(u);
  return (pathCache[key] = path);
}
function quadPts(g, n){ const pts = []; for (let i = 0; i <= n; i++){ const t = i/n, u = 1 - t; pts.push({x:u*u*g.p0.x + 2*u*t*g.c.x + t*t*g.p1.x, y:u*u*g.p0.y + 2*u*t*g.c.y + t*t*g.p1.y}); } return pts; }
function routePts(a, b, tunnelId){
  if (tunnelId && tunnelGeom[tunnelId] && settings.tunnels){
    const g = tunnelGeom[tunnelId]; const pts = quadPts(g, 24);
    return g.a === a ? pts : pts.reverse();
  }
  const p = bfsPath(a, b); if (!p) return null;
  return p.map(id => pos[id]).filter(Boolean);
}
function computeTunnelGeom(){
  tunnelGeom = {};
  if (!live) return;
  const count = {};
  for (const t of live.tunnels){
    const a = pos[t.a], b = pos[t.b]; if (!a || !b) continue;
    const key = [t.a, t.b].sort().join('|'); const i = count[key] = (count[key] || 0) + 1;
    const mx = (a.x + b.x)/2, my = (a.y + b.y)/2, dx = b.x - a.x, dy = b.y - a.y, d = Math.hypot(dx, dy) || 1;
    const off = (60 + 30*(i-1)) * (t.a < t.b ? 1 : -1);
    tunnelGeom[t.id] = {a:t.a, b:t.b, p0:a, p1:b, c:{x:mx - dy/d*off, y:my + dx/d*off}, t};
  }
}

// ------------------------------------------------------------ drawing primitives
function rr(x, y, w, h, r){ ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }
function poly(x, y, r, n, rot){ for (let i = 0; i < n; i++){ const a = rot + i*2*Math.PI/n; i ? ctx.lineTo(x + r*Math.cos(a), y + r*Math.sin(a)) : ctx.moveTo(x + r*Math.cos(a), y + r*Math.sin(a)); } ctx.closePath(); }
function arrow(x1, y1, x2, y2){ ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); const a = Math.atan2(y2 - y1, x2 - x1); ctx.moveTo(x2, y2); ctx.lineTo(x2 - 4*Math.cos(a - .6), y2 - 4*Math.sin(a - .6)); ctx.moveTo(x2, y2); ctx.lineTo(x2 - 4*Math.cos(a + .6), y2 - 4*Math.sin(a + .6)); ctx.stroke(); }
function pill(text, x, y, fg, bg, font, border){
  ctx.font = font || '600 10.5px system-ui,sans-serif';
  const w = ctx.measureText(text).width + 9, h = 15;
  ctx.beginPath(); rr(x - w/2, y - h/2, w, h, 7); ctx.fillStyle = bg; ctx.fill();
  if (border){ ctx.strokeStyle = border; ctx.lineWidth = 1; ctx.stroke(); }
  ctx.fillStyle = fg; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText(text, x, y + .5);
  return w;
}
function lock(x, y, color){
  ctx.save(); ctx.strokeStyle = color; ctx.fillStyle = color; ctx.lineWidth = 1.8;
  ctx.beginPath(); ctx.arc(x, y - 3, 3.6, Math.PI, 0); ctx.stroke();
  ctx.beginPath(); rr(x - 5, y - 3, 10, 8, 1.5); ctx.fill(); ctx.restore();
}
function shape(kind, x, y, fill, stroke){
  ctx.beginPath();
  switch (kind){
    case 'switch': rr(x - 27, y - 14, 54, 28, 6); break;
    case 'controller': poly(x, y, 22, 6, Math.PI/6); break;
    case 'router': case 'nat': ctx.arc(x, y, 19, 0, Math.PI*2); break;
    case 'firewall': poly(x, y, 21, 8, Math.PI/8); break;
    case 'server': rr(x - 15, y - 20, 30, 40, 5); break;
    case 'vpn-gw': case 'gateway': poly(x, y, 23, 4, 0); break;
    default: rr(x - 19, y - 15, 38, 30, 7);
  }
  ctx.fillStyle = fill; ctx.fill(); ctx.lineWidth = 2; ctx.strokeStyle = stroke; ctx.stroke();
  ctx.strokeStyle = 'rgba(255,255,255,.95)'; ctx.fillStyle = 'rgba(255,255,255,.95)'; ctx.lineWidth = 1.7;
  if (kind === 'switch'){ arrow(x - 15, y - 5, x + 15, y - 5); arrow(x + 15, y + 5, x - 15, y + 5); }
  else if (kind === 'router' || kind === 'nat'){ arrow(x - 3, y - 3, x - 11, y - 11); arrow(x + 3, y + 3, x + 11, y + 11); arrow(x - 11, y + 11, x - 3, y + 3); arrow(x + 11, y - 11, x + 3, y - 3); }
  else if (kind === 'controller'){ ctx.font = '700 13px system-ui,sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText('C', x, y + 1); }
  else if (kind === 'firewall'){ ctx.beginPath(); for (const dy of [-6, 0, 6]){ ctx.moveTo(x - 10, y + dy); ctx.lineTo(x + 10, y + dy); } ctx.moveTo(x - 3, y - 6); ctx.lineTo(x - 3, y); ctx.moveTo(x + 4, y); ctx.lineTo(x + 4, y + 6); ctx.stroke(); }
  else if (kind === 'server'){ ctx.beginPath(); for (const dy of [-10, -3, 4]){ ctx.moveTo(x - 8, y + dy); ctx.lineTo(x + 8, y + dy); } ctx.stroke(); ctx.beginPath(); ctx.arc(x + 6, y + 12, 1.8, 0, 7); ctx.fill(); }
  else if (kind === 'vpn-gw' || kind === 'gateway'){ lock(x, y + 1, 'rgba(255,255,255,.95)'); }
  else { ctx.beginPath(); rr(x - 11, y - 9, 22, 13, 2); ctx.stroke(); ctx.beginPath(); ctx.moveTo(x - 5, y + 9); ctx.lineTo(x + 5, y + 9); ctx.moveTo(x, y + 4); ctx.lineTo(x, y + 9); ctx.stroke(); }
}

// ------------------------------------------------------------ render loop
function draw(now){
  ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  ctx.fillStyle = C.canvas; ctx.fillRect(0, 0, W, H);
  if (!topo.nodes.length){ requestAnimationFrame(draw); return; }
  if (force) for (let i = 0; i < 3 && force; i++) stepForce();
  ctx.translate(view.x, view.y); ctx.scale(view.k, view.k);
  computeTunnelGeom();
  const mode = colorMode(), t = now/1000;
  const L = live ? live.links : {};
  const lowZoom = view.k < .55;

  // group halos (soft bubbles behind members)
  if (mode !== 'none' && live){
    for (const n of topo.nodes){
      const p = pos[n.id]; if (!p) continue;
      const gs = groupsOf(n.id, mode); if (!gs.length) continue;
      ctx.globalAlpha = nodeInFocus(n.id) ? .13 : .04;
      gs.forEach(g => { ctx.beginPath(); ctx.arc(p.x, p.y, 46, 0, Math.PI*2); ctx.fillStyle = g.color; ctx.fill(); });
    }
    ctx.globalAlpha = 1;
  }
  // control channels
  if (settings.control){
    ctx.setLineDash([3, 6]); ctx.lineWidth = 1.2; ctx.strokeStyle = C.controller; ctx.globalAlpha = focusGroup ? .12 : .4;
    for (const c of topo.nodes) if (c.type === 'controller' && pos[c.id])
      for (const s of topo.nodes) if (s.type === 'switch' && pos[s.id]){ ctx.beginPath(); ctx.moveTo(pos[c.id].x, pos[c.id].y); ctx.lineTo(pos[s.id].x, pos[s.id].y); ctx.stroke(); }
    ctx.setLineDash([]); ctx.globalAlpha = 1;
  }
  // highlighted paths (ping animations, warnings)
  const hl = {};
  anims.forEach(a => (a.links || []).forEach(id => hl[id] = a.ok ? C.ok : C.danger));
  if (warnFlash && now < warnFlash.until) warnFlash.links.forEach(id => hl[id] = '#f59e0b');
  // links
  for (const l of topo.links){
    const a = pos[l.a], b = pos[l.b]; if (!a || !b) continue;
    const s = L[l.id] || {}; const up = s.up !== false; const bps = s.bps || 0;
    const isSel = sel && sel.kind === 'link' && sel.id === l.id, isHov = hover && hover.kind === 'link' && hover.id === l.id;
    ctx.globalAlpha = linkInFocus(l) ? 1 : .12;
    if (hl[l.id]){ ctx.strokeStyle = hl[l.id]; ctx.globalAlpha *= .35; ctx.lineWidth = 12; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); ctx.globalAlpha = linkInFocus(l) ? 1 : .12; }
    const w = 2 + (bps > 1000 ? Math.min(6, Math.log10(bps) - 3) : 0);
    ctx.setLineDash(up ? [] : [7, 6]);
    ctx.strokeStyle = !up ? C.danger : (isSel ? C.accent : (bps > 1000 ? C.linkActive : C.link));
    ctx.lineWidth = w + (isSel || isHov ? 2 : 0);
    ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
    ctx.setLineDash([]);
  }
  ctx.globalAlpha = 1;
  // tunnels
  if (settings.tunnels){
    for (const g of Object.values(tunnelGeom)){
      const isSel = sel && sel.kind === 'tunnel' && sel.id === g.t.id;
      ctx.globalAlpha = focusGroup ? .35 : 1;
      ctx.strokeStyle = g.t.color; ctx.lineWidth = isSel ? 5 : 3; ctx.setLineDash([10, 6]); ctx.lineDashOffset = -t*12;
      ctx.beginPath(); ctx.moveTo(g.p0.x, g.p0.y); ctx.quadraticCurveTo(g.c.x, g.c.y, g.p1.x, g.p1.y); ctx.stroke();
      ctx.setLineDash([]); ctx.lineDashOffset = 0;
      const m = quadPts(g, 2)[1];
      const w = pill('      ' + g.t.label, m.x, m.y, '#fff', g.t.color, '700 11px system-ui,sans-serif');
      lock(m.x - w/2 + 10, m.y + 1, '#fff');
    }
    ctx.globalAlpha = 1;
  }
  // link labels
  if (!lowZoom) for (const l of topo.links){
    const a = pos[l.a], b = pos[l.b]; if (!a || !b) continue;
    if (!linkInFocus(l)) continue;
    const s = L[l.id] || {}; const d = Math.hypot(b.x - a.x, b.y - a.y) || 1;
    if (settings.intf){
      const off = Math.min(.42, 40/d);
      pill(l.ia, a.x + (b.x - a.x)*off, a.y + (b.y - a.y)*off, C.muted, C.labelBg, '500 10px ui-monospace,monospace', C.border);
      pill(l.ib, b.x + (a.x - b.x)*off, b.y + (a.y - b.y)*off, C.muted, C.labelBg, '500 10px ui-monospace,monospace', C.border);
    }
    const mx = (a.x + b.x)/2, my = (a.y + b.y)/2; let dy = 0;
    const bothSw = nodeById[l.a] && nodeById[l.b] && nodeById[l.a].type === 'switch' && nodeById[l.b].type === 'switch';
    if (live && live.vlans && bothSw && (mode === 'vlan' || settings.intf)){
      const txt = s.carries == null ? 'all VLANs' : (s.carries.length ? 'VLAN ' + s.carries.join(',') : 'no VLANs');
      pill(txt, mx, my, C.text, C.labelBg, '600 10.5px system-ui,sans-serif', C.border); dy = 17;
    }
    if (s.note){ pill(s.note, mx, my + dy, C.accent, C.labelBg, '600 10.5px system-ui,sans-serif', C.accent); dy += 17; }
    if (settings.rates && s.bps > 1000) pill(fmtRate(s.bps), mx, my + dy, C.linkActive, C.labelBg, '600 10.5px system-ui,sans-serif');
    if (s.up === false) pill('DOWN', mx, my + dy, '#fff', C.danger);
  }
  // traffic dots
  if (settings.traffic && live){
    for (const c of live.connections){
      if (c.ext) continue;
      if (focusGroup && !(nodeInFocus(c.a) && nodeInFocus(c.b))) continue;
      const pts = routePts(c.a, c.b, c.tunnel); if (!pts || pts.length < 2) continue;
      const L2 = polyLen(pts); if (L2 < 1) continue;
      const seed = (c.aport*7 + c.bport*13) % 1000 / 1000;
      const sp = 90/L2;
      for (let k = 0; k < 3; k++){
        const f = ((t*sp + seed + k/3) % 1 + 1) % 1;
        const p = along(pts, f);
        ctx.beginPath(); ctx.arc(p.x, p.y, 4.2, 0, Math.PI*2); ctx.fillStyle = c.color; ctx.fill();
        ctx.lineWidth = 1.2; ctx.strokeStyle = C.canvas; ctx.stroke();
      }
    }
  }
  // ping animations
  anims = anims.filter(a => now - a.t0 < a.dur + 1800);
  for (const a of anims){
    if (!a.pts || a.pts.length < 2) continue;
    const prog = Math.min(1, (now - a.t0)/a.dur);
    const f = a.ok ? (prog < .5 ? prog*2 : 2 - prog*2) : Math.min(.5, prog);
    const p = along(a.pts, f);
    ctx.beginPath(); ctx.arc(p.x, p.y, 7, 0, Math.PI*2); ctx.fillStyle = a.ok ? C.ok : C.danger; ctx.fill();
    ctx.lineWidth = 2; ctx.strokeStyle = '#fff'; ctx.stroke();
    if (!a.ok && prog >= 1){ ctx.strokeStyle = C.danger; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(p.x - 9, p.y - 9); ctx.lineTo(p.x + 9, p.y + 9); ctx.moveTo(p.x + 9, p.y - 9); ctx.lineTo(p.x - 9, p.y + 9); ctx.stroke(); }
  }
  // nodes
  for (const n of topo.nodes){
    const p = pos[n.id]; if (!p) continue;
    const s = live && live.nodes[n.id];
    ctx.globalAlpha = nodeInFocus(n.id) ? 1 : .18;
    const role = nodeRole(n); const kind = n.type === 'controller' ? 'controller' : (n.type === 'switch' ? 'switch' : role);
    if (flashes[n.id] && now < flashes[n.id]){
      const pulse = .5 + .5*Math.sin(now/120);
      ctx.beginPath(); ctx.arc(p.x, p.y, 30 + pulse*6, 0, Math.PI*2); ctx.fillStyle = 'rgba(239,68,68,' + (.18 + .2*pulse) + ')'; ctx.fill();
    }
    if (mode !== 'none'){
      const gs = groupsOf(n.id, mode);
      if (gs.length > (n.type === 'host' ? 1 : 0)){
        const seg = Math.PI*2/gs.length;
        gs.forEach((g, i) => { ctx.beginPath(); ctx.arc(p.x, p.y, 30, -Math.PI/2 + i*seg, -Math.PI/2 + (i+1)*seg); ctx.strokeStyle = g.color; ctx.lineWidth = 5; ctx.stroke(); });
      }
    }
    const isSel = sel && sel.kind === 'node' && sel.id === n.id;
    const picked = pingPick.includes(n.id);
    if (isSel || picked || (hover && hover.kind === 'node' && hover.id === n.id)){
      ctx.beginPath(); ctx.arc(p.x, p.y, 34, 0, Math.PI*2); ctx.strokeStyle = picked ? C.ok : C.accent; ctx.lineWidth = isSel || picked ? 3 : 1.5; ctx.stroke();
    }
    shape(kind, p.x, p.y, nodeFill(n), C.canvas);
    // labels
    ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
    ctx.font = '700 12.5px system-ui,sans-serif'; ctx.fillStyle = C.text;
    const by = p.y + (kind === 'server' ? 36 : 32);
    ctx.fillText(n.id, p.x, by);
    if (!lowZoom){
      let sub = '';
      if (n.type === 'host') sub = primaryIp(n.id);
      if (role !== n.type && n.type === 'host' && role !== 'host') sub = role + (sub ? ' · ' + sub : '');
      if (sub){ ctx.font = '500 10.5px system-ui,sans-serif'; ctx.fillStyle = C.muted; ctx.fillText(sub, p.x, by + 13); }
    }
    // badges
    if (s){
      let bx = p.x + 22, byy = p.y - 22;
      if (s.aclRules > 0){ const w = pill('ACL', bx + 10, byy, '#fff', C.firewall); bx += w + 2; }
      if (s.dropDelta > 0){ pill('-' + s.dropDelta, bx + 12, byy, '#fff', C.danger); }
      if (isTunnelEndpoint(n.id)){ ctx.beginPath(); ctx.arc(p.x - 22, p.y - 22, 9, 0, Math.PI*2); ctx.fillStyle = '#c026d3'; ctx.fill(); lock(p.x - 22, p.y - 21, '#fff'); }
      if (s.note && !lowZoom){ ctx.beginPath(); ctx.arc(p.x + 22, p.y + 18, 6, 0, Math.PI*2); ctx.fillStyle = C.accent; ctx.fill(); ctx.fillStyle = '#fff'; ctx.font = '700 9px system-ui'; ctx.textBaseline = 'middle'; ctx.fillText('i', p.x + 22, p.y + 18.5); }
    }
  }
  ctx.globalAlpha = 1;
  requestAnimationFrame(draw);
}

// ------------------------------------------------------------ hit testing
function toWorld(e){ const r = cv.getBoundingClientRect(); return {x:(e.clientX - r.left - view.x)/view.k, y:(e.clientY - r.top - view.y)/view.k}; }
function hitNode(p){ let best = null, bd = 30; for (const n of topo.nodes){ const q = pos[n.id]; if (!q) continue; const d = Math.hypot(q.x - p.x, q.y - p.y); if (d < bd){ bd = d; best = n; } } return best; }
function distSeg(p, a, b){ const dx = b.x - a.x, dy = b.y - a.y, l2 = dx*dx + dy*dy || 1; let t = ((p.x - a.x)*dx + (p.y - a.y)*dy)/l2; t = Math.max(0, Math.min(1, t)); return Math.hypot(p.x - a.x - t*dx, p.y - a.y - t*dy); }
function hitLink(p){ const tol = 7/view.k + 2; let best = null, bd = tol; for (const l of topo.links){ const a = pos[l.a], b = pos[l.b]; if (!a || !b) continue; const d = distSeg(p, a, b); if (d < bd){ bd = d; best = l; } } return best; }
function hitTunnel(p){ if (!settings.tunnels) return null; const tol = 8/view.k + 2; for (const g of Object.values(tunnelGeom)){ const pts = quadPts(g, 24); for (let i = 1; i < pts.length; i++) if (distSeg(p, pts[i-1], pts[i]) < tol) return g.t; } return null; }
function hitAny(p){
  const n = hitNode(p); if (n) return {kind:'node', id:n.id};
  const tu = hitTunnel(p); if (tu) return {kind:'tunnel', id:tu.id};
  const l = hitLink(p); if (l) return {kind:'link', id:l.id};
  return null;
}

// ------------------------------------------------------------ interaction
cv.addEventListener('pointerdown', e => {
  cv.setPointerCapture(e.pointerId);
  const p = toWorld(e), n = hitNode(p);
  drag = n ? {mode:'node', id:n.id, sx:e.clientX, sy:e.clientY, moved:false, shift:e.shiftKey}
           : {mode:'pan', sx:e.clientX, sy:e.clientY, vx:view.x, vy:view.y, moved:false};
  cv.classList.add('dragging');
});
cv.addEventListener('pointermove', e => {
  if (drag){
    const dx = e.clientX - drag.sx, dy = e.clientY - drag.sy;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    if (drag.mode === 'node' && drag.moved){ pos[drag.id] = toWorld(e); pathCache = {}; }
    else if (drag.mode === 'pan'){ view.x = drag.vx + dx; view.y = drag.vy + dy; }
    $('#tooltip').style.display = 'none';
    return;
  }
  hover = hitAny(toWorld(e));
  showTooltip(e);
});
cv.addEventListener('pointerleave', () => { hover = null; $('#tooltip').style.display = 'none'; });
cv.addEventListener('pointerup', e => {
  cv.classList.remove('dragging');
  const d = drag; drag = null; if (!d) return;
  if (d.moved){ if (d.mode === 'node') saveLayout(); return; }
  const hit = hitAny(toWorld(e));
  if (hit && hit.kind === 'node' && (e.shiftKey || d.shift) && nodeById[hit.id].type === 'host'){ pickForPing(hit.id); return; }
  select(hit);
});
cv.addEventListener('wheel', e => {
  e.preventDefault();
  const r = cv.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top;
  const k = Math.max(.15, Math.min(4, view.k*Math.exp(-e.deltaY*.0015)));
  view.x = mx - (mx - view.x)*k/view.k; view.y = my - (my - view.y)*k/view.k; view.k = k;
}, {passive:false});
window.addEventListener('keydown', e => {
  if (/INPUT|SELECT|TEXTAREA/.test(document.activeElement.tagName)) return;
  if (e.key === 'Escape'){ select(null); focusGroup = null; pingPick = []; updatePickbar(); renderLegend(); }
  if (e.key === 'f' || e.key === 'F') fitView();
});
function showTooltip(e){
  const tt = $('#tooltip');
  if (!hover || !live){ tt.style.display = 'none'; return; }
  let h = '';
  if (hover.kind === 'node'){
    const n = nodeById[hover.id], s = live.nodes[hover.id] || {};
    h = '<b>' + esc(n.id) + '</b> <span class="muted">' + esc(nodeRole(n)) + '</span>';
    (s.addrs || []).forEach(a => h += '<br><span class="mono">' + esc(a.cidr) + '</span> <span class="muted">' + esc(a.iface) + (a.tunnel ? ' (tunnel)' : '') + '</span>');
    if (n.type === 'switch' && s.flows != null) h += '<br><span class="muted">' + s.flows + ' flow rules</span>';
    if (s.aclRules) h += '<br><span style="color:var(--err)">' + s.aclRules + ' blocking rule(s), ' + s.drops + ' pkts dropped</span>';
    if (s.note) h += '<br><i>' + esc(s.note) + '</i>';
  } else if (hover.kind === 'link'){
    const l = linkById[hover.id], s = live.links[hover.id] || {};
    h = '<b class="mono">' + esc(l.ia) + ' ⇄ ' + esc(l.ib) + '</b><br>' + (s.up === false ? '<span class="down">DOWN</span>' : '<span class="up">up</span>') + ' · ' + fmtRate(s.bps);
    if (live.vlans) h += '<br>VLANs: ' + (s.carries == null ? 'all' : (s.carries.join(', ') || 'none'));
    const pr = l.params || {}; const ps = Object.entries(pr).map(([k, v]) => k + '=' + v).join(' ');
    if (ps) h += '<br><span class="muted">' + esc(ps) + '</span>';
  } else {
    const t = live.tunnels.find(x => x.id === hover.id);
    if (t) h = '<b>' + esc(t.label) + '</b><br>' + esc(t.a) + ' ⇄ ' + esc(t.b) + '<br><span class="muted">' + esc(t.kind) + (t.auto ? ', auto-detected' : ', annotated') + '</span>';
  }
  const r = stage.getBoundingClientRect();
  tt.innerHTML = h; tt.style.display = 'block';
  let x = e.clientX - r.left + 14, y = e.clientY - r.top + 14;
  if (x + tt.offsetWidth > W - 8) x = e.clientX - r.left - tt.offsetWidth - 14;
  if (y + tt.offsetHeight > H - 8) y = e.clientY - r.top - tt.offsetHeight - 14;
  tt.style.left = x + 'px'; tt.style.top = y + 'px';
}
function select(hit){
  sel = hit;
  deep = null;
  if (hit && hit.kind === 'node') loadDeep(hit.id);
  renderDetails(); renderDeep();
  if (hit) switchTab('details');
}
function pickForPing(id){
  if (pingPick.includes(id)) pingPick = pingPick.filter(x => x !== id); else pingPick.push(id);
  updatePickbar();
  if (pingPick.length === 2){
    const [a, b] = pingPick; pingPick = []; updatePickbar();
    $('#pSrc').value = a; $('#pDst').value = b; updateIpSelect();
    switchTab('tests'); runPing(a, b, null, +$('#pCount').value || 3);
  }
}
function updatePickbar(){ const pb = $('#pickbar'); if (pingPick.length === 1){ pb.textContent = 'Ping from ' + pingPick[0] + ' — Shift+click the destination host (Esc to cancel)'; pb.style.display = 'block'; } else pb.style.display = 'none'; }

// ------------------------------------------------------------ panels
function switchTab(name){
  $$('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab').forEach(t => t.classList.toggle('active', t.id === 'tab-' + name));
  if (name === 'events'){ unseenEv = 0; $('#evBadge').textContent = ''; }
}
$$('.tabs button').forEach(b => b.addEventListener('click', () => switchTab(b.dataset.tab)));
const activeTab = () => ($('.tabs button.active') || {}).dataset.tab;

function renderLegend(){
  const el = $('#legend'); if (!live){ el.innerHTML = ''; return; }
  const mode = colorMode(); let h = '';
  const gs = (live.groups || {})[mode] || {};
  const names = Object.keys(gs);
  if (mode !== 'none' && names.length){
    h += '<span class="lg-title">' + ({vlan:'VLANs', subnet:'Subnets', custom:'Groups'}[mode]) + '</span>';
    names.forEach(n => h += '<span class="chip' + (focusGroup && focusGroup.name === n && focusGroup.mode === mode ? ' focus' : '') + '" data-group="' + esc(n) + '" title="Click to focus"><span class="dot" style="background:' + esc(gs[n].color) + '"></span>' + esc(n) + ' <span class="muted">' + gs[n].members.length + '</span></span>');
  } else {
    h += '<span class="lg-title">Nodes</span>';
    [['Host', C.host], ['Switch', C.switch], ['Router/NAT', C.router], ['Firewall', C.firewall], ['Controller', C.controller]].forEach(([n, c]) => h += '<span class="chip static"><span class="dot" style="background:' + c + '"></span>' + n + '</span>');
  }
  if (settings.traffic && live.connections.length){
    const used = {}; live.connections.forEach(c => used[c.cls] = c.color);
    h += '<span class="lg-title">Traffic</span>';
    Object.entries(used).forEach(([n, c]) => h += '<span class="chip static"><span class="dot" style="background:' + esc(c) + '"></span>' + esc(n) + '</span>');
  }
  if (settings.tunnels && live.tunnels.length){
    const kinds = {}; live.tunnels.forEach(t => kinds[t.label] = t.color);
    h += '<span class="lg-title">Tunnels</span>';
    Object.entries(kinds).forEach(([n, c]) => h += '<span class="chip static"><span class="sq" style="background:' + esc(c) + '"></span>' + esc(n) + '</span>');
  }
  el.innerHTML = h;
  el.querySelectorAll('[data-group]').forEach(c => c.addEventListener('click', () => {
    const name = c.dataset.group;
    focusGroup = (focusGroup && focusGroup.name === name && focusGroup.mode === mode) ? null : {mode, name};
    renderLegend();
  }));
}

function connRow(c){
  const via = c.tunnel ? (live.tunnels.find(t => t.id === c.tunnel) || {}).label : '';
  return '<tr><td><span class="dot" style="background:' + esc(c.color) + '"></span> ' + esc(c.cls) + '<div class="muted">' + c.proto.toUpperCase() + (via ? ' · via ' + esc(via) : '') + '</div></td>' +
    '<td class="mono">' + esc(c.a.replace(/^ext:/, '')) + ':' + c.aport + '<br>→ ' + esc(c.b.replace(/^ext:/, '')) + ':' + c.bport + '</td>' +
    '<td>' + esc(c.sproc || c.cproc || '') + '</td></tr>';
}
function summaryHTML(){
  const hosts = topo.nodes.filter(n => n.type === 'host').length, sws = topo.nodes.filter(n => n.type === 'switch').length, ctl = topo.nodes.filter(n => n.type === 'controller').length;
  let h = '<h3>Network</h3><div class="stats">' +
    [[hosts, 'Hosts'], [sws, 'Switches'], [ctl, 'Controllers'], [topo.links.length, 'Links'], [live ? live.tunnels.length : 0, 'Tunnels'], [live ? live.connections.length : 0, 'Flows']]
      .map(([v, l]) => '<div class="stat"><b>' + v + '</b><span>' + l + '</span></div>').join('') + '</div>';
  if (live){
    if (live.warnings.length){
      h += '<h3>Checks</h3>';
      live.warnings.forEach((w, i) => h += '<div class="warn ' + esc(w.level) + '" data-w="' + i + '">' + esc(w.text) + '</div>');
    }
    const mode = colorMode(), gs = (live.groups || {})[mode] || {};
    if (mode !== 'none' && Object.keys(gs).length){
      h += '<h3>' + ({vlan:'VLANs', subnet:'Subnets', custom:'Groups'}[mode]) + '</h3><table>';
      Object.entries(gs).forEach(([n, g]) => h += '<tr><td><span class="dot" style="background:' + esc(g.color) + '"></span> ' + esc(n) + '</td><td>' + g.members.map(esc).join(', ') + '</td></tr>');
      h += '</table>';
    }
    if (live.tunnels.length){
      h += '<h3>Tunnels / VPNs</h3><table>';
      live.tunnels.forEach(t => h += '<tr><td><span class="sq" style="background:' + esc(t.color) + '"></span> ' + esc(t.label) + '</td><td>' + esc(t.a) + ' ⇄ ' + esc(t.b) + '</td><td class="muted">' + (t.auto ? 'detected' : 'annotated') + '</td></tr>');
      h += '</table>';
    }
    const acl = topo.nodes.filter(n => live.nodes[n.id] && live.nodes[n.id].aclRules);
    if (acl.length){
      h += '<h3>Access control</h3><table><tr><th>Node</th><th>Blocking rules</th><th class="num">Dropped</th></tr>';
      acl.forEach(n => { const s = live.nodes[n.id]; h += '<tr><td>' + esc(n.id) + '</td><td>' + s.aclRules + (n.type === 'switch' ? ' flow' : ' iptables') + '</td><td class="num">' + s.drops + '</td></tr>'; });
      h += '</table>';
    }
  }
  h += '<p class="muted" style="margin-top:14px">Click a node, link or tunnel for details. Click a legend chip to focus a group.</p>';
  return h;
}
function ifaceTable(s, isSwitch){
  let h = '<table><tr><th>Interface</th><th>' + (isSwitch ? 'VLAN config' : 'Addresses') + '</th><th class="num">RX / TX</th></tr>';
  (s.ifaces || []).forEach(i => {
    const st = i.up === false ? '<span class="down">●</span>' : (i.up ? '<span class="up">●</span>' : '<span class="muted">●</span>');
    const extra = i.kind ? ' <span class="tag">' + esc(i.kind) + '</span>' : (i.vlan != null ? ' <span class="tag">VLAN ' + i.vlan + '</span>' : '');
    const col = isSwitch ? esc(i.vlanPort || (i.ips.length ? i.ips.join(', ') : '—')) : (i.ips.map(esc).join('<br>') || '—') + (i.mac ? '<div class="muted mono">' + esc(i.mac) + '</div>' : '');
    h += '<tr><td class="mono">' + st + ' ' + esc(i.name) + extra + '</td><td>' + col + '</td><td class="num">' + fmtRate(i.rx_bps) + '<br>' + fmtRate(i.tx_bps) + '</td></tr>';
  });
  return h + '</table>';
}
function nodeHTML(id){
  const n = nodeById[id]; if (!n) return summaryHTML();
  const s = (live && live.nodes[id]) || {}; const role = nodeRole(n);
  let h = '<div class="dhead"><span class="dot" style="width:14px;height:14px;background:' + esc(nodeFill(n)) + '"></span><h2>' + esc(id) + '</h2><span class="tag">' + esc(role) + '</span><span class="tag">' + esc(n.cls) + '</span></div>';
  if (s.note) h += '<div class="note">' + esc(s.note) + '</div>';
  if (n.type === 'controller'){ h += '<p>Address: <span class="mono">' + esc(n.ctrl) + '</span></p>'; return h; }
  const gl = ['vlan', 'subnet', 'custom'].flatMap(m => groupsOf(id, m).map(g => '<span class="chip static"><span class="dot" style="background:' + esc(g.color) + '"></span>' + esc(g.name) + '</span>'));
  if (gl.length) h += '<div style="display:flex;gap:5px;flex-wrap:wrap;margin:6px 0">' + gl.join('') + '</div>';
  if (n.type === 'switch') h += '<p class="muted" style="margin:4px 0">DPID ' + esc(n.dpid || '?') + ' · ' + (s.flows != null ? s.flows : '?') + ' flow rules</p>';
  h += '<h3>Interfaces</h3>' + ifaceTable(s, n.type === 'switch');
  if (s.aclRules) h += '<h3>Access control</h3><p style="margin:0">' + s.aclRules + ' blocking ' + (n.type === 'switch' ? 'flow rule(s)' : 'iptables rule(s)/policies') + ', <b>' + s.drops + '</b> packets dropped' + (s.dropDelta ? ' <span class="down">(+' + s.dropDelta + ' just now)</span>' : '') + '</p>';
  if (s.listen && s.listen.length) h += '<h3>Listening services</h3><div style="display:flex;gap:5px;flex-wrap:wrap">' + s.listen.map(l => '<span class="chip static mono">' + l.proto + '/' + l.port + (l.proc ? ' <span class="muted">' + esc(l.proc) + '</span>' : '') + '</span>').join('') + '</div>';
  const cs = live ? live.connections.filter(c => c.a === id || c.b === id) : [];
  if (cs.length) h += '<h3>Active flows</h3><table class="conn">' + cs.map(connRow).join('') + '</table>';
  if (n.type === 'host') h += '<div style="margin-top:12px"><button id="btnPingFrom">Ping from ' + esc(id) + '…</button></div>';
  return h;
}
function linkHTML(id){
  const l = linkById[id]; if (!l) return summaryHTML();
  const s = (live && live.links[id]) || {};
  let h = '<div class="dhead"><h2>' + esc(l.a) + ' ⇄ ' + esc(l.b) + '</h2><span class="tag">link</span>' + (s.up === false ? '<span class="tag down">DOWN</span>' : '<span class="tag up">up</span>') + '</div>';
  if (s.note) h += '<div class="note">' + esc(s.note) + '</div>';
  h += '<table><tr><th>End</th><th>Interface</th>' + (live && live.vlans ? '<th>VLAN config</th>' : '') + '</tr>' +
    '<tr><td>' + esc(l.a) + '</td><td class="mono">' + esc(l.ia) + '</td>' + (live && live.vlans ? '<td>' + esc(s.portA || '—') + '</td>' : '') + '</tr>' +
    '<tr><td>' + esc(l.b) + '</td><td class="mono">' + esc(l.ib) + '</td>' + (live && live.vlans ? '<td>' + esc(s.portB || '—') + '</td>' : '') + '</tr></table>';
  h += '<h3>Traffic</h3><p style="margin:0">' + fmtRate(s.bps) + ' · ' + (s.pps || 0).toFixed(1) + ' pkt/s</p>';
  if (live && live.vlans) h += '<h3>VLANs carried</h3><p style="margin:0">' + (s.carries == null ? 'All (no restriction)' : (s.carries.join(', ') || 'None')) + '</p>';
  const pr = Object.entries(l.params || {});
  if (pr.length) h += '<h3>Link parameters (TCLink)</h3><table>' + pr.map(([k, v]) => '<tr><td>' + esc(k) + '</td><td>' + esc(v) + '</td></tr>').join('') + '</table>';
  const cs = live ? live.connections.filter(c => { const p = c.tunnel ? null : bfsPath(c.a, c.b); if (!p) return false; for (let i = 1; i < p.length; i++) if ((p[i-1] === l.a && p[i] === l.b) || (p[i-1] === l.b && p[i] === l.a)) return true; return false; }) : [];
  if (cs.length) h += '<h3>Flows crossing this link</h3><table class="conn">' + cs.map(connRow).join('') + '</table>';
  return h;
}
function tunnelHTML(id){
  const t = live && live.tunnels.find(x => x.id === id); if (!t) return summaryHTML();
  let h = '<div class="dhead"><span class="sq" style="width:16px;background:' + esc(t.color) + '"></span><h2>' + esc(t.label) + '</h2><span class="tag">' + esc(t.kind) + '</span><span class="tag">' + (t.auto ? 'auto-detected' : 'annotated') + '</span></div>';
  h += '<table><tr><th>Endpoint</th><th>Tunnel interface</th><th>Addresses</th></tr>';
  [t.a, t.b].forEach(e => { const ifn = t.ifaces[e]; const s = live.nodes[e] || {}; const ad = (s.addrs || []).filter(a => !ifn || a.iface === ifn).map(a => a.cidr); h += '<tr><td>' + esc(e) + '</td><td class="mono">' + esc(ifn || '—') + '</td><td class="mono">' + ad.map(esc).join('<br>') + '</td></tr>'; });
  h += '</table>';
  const cs = live.connections.filter(c => c.tunnel === id);
  h += '<h3>Flows inside the tunnel</h3>' + (cs.length ? '<table class="conn">' + cs.map(connRow).join('') + '</table>' : '<p class="muted" style="margin:0">None right now. ICMP is not listed (only TCP/UDP sockets) — use the Ping test to send traffic through it.</p>');
  return h;
}
function renderDetails(){
  const el = $('#detLive');
  let h;
  if (!sel) h = summaryHTML();
  else if (sel.kind === 'node') h = nodeHTML(sel.id);
  else if (sel.kind === 'link') h = linkHTML(sel.id);
  else h = tunnelHTML(sel.id);
  el.innerHTML = h;
  el.querySelectorAll('[data-w]').forEach(d => d.addEventListener('click', () => { const w = live.warnings[+d.dataset.w]; warnFlash = {links:w.links || [], until:performance.now() + 4000}; }));
  const pf = $('#btnPingFrom'); if (pf) pf.addEventListener('click', () => { $('#pSrc').value = sel.id; switchTab('tests'); });
}
async function loadDeep(id){
  deep = {id, loading:true, sections:[]}; renderDeep();
  try { const r = await api('/api/node?name=' + encodeURIComponent(id)); if (deep && deep.id === id){ deep = {id, sections:r.sections, t:Date.now()}; renderDeep(); } }
  catch(e){ if (deep && deep.id === id){ deep = {id, error:e.message}; renderDeep(); } }
}
function renderDeep(){
  const el = $('#detDeep');
  if (!deep || !sel || sel.kind !== 'node' || deep.id !== sel.id){ el.innerHTML = ''; return; }
  const open = new Set($$('#detDeep details[open]').map(d => d.dataset.k));
  let h = '<div class="row" style="margin-top:16px"><h3 style="margin:0">Live from ' + esc(deep.id) + '</h3><button id="btnDeep">' + (deep.loading ? 'Loading…' : 'Refresh') + '</button></div>';
  if (deep.error) h += '<p class="down">' + esc(deep.error) + '</p>';
  if (deep.sections) deep.sections.forEach(s => h += '<details data-k="' + esc(s.title) + '"' + (open.has(s.title) ? ' open' : '') + '><summary>' + esc(s.title) + '</summary><pre>' + esc(s.body) + '</pre></details>');
  if (deep.sections && !deep.sections.length && !deep.loading && !deep.error) h += '<p class="muted">No output (node may not be running).</p>';
  el.innerHTML = h;
  const b = $('#btnDeep'); if (b) b.addEventListener('click', () => loadDeep(deep.id));
}
function renderTraffic(){
  const el = $('#tab-traffic'); if (!live){ el.innerHTML = ''; return; }
  const cs = live.connections;
  let h = '<h3>Active flows (' + cs.length + ')</h3>';
  if (cs.length){
    const by = {}; cs.forEach(c => { by[c.cls] = by[c.cls] || {n:0, color:c.color}; by[c.cls].n++; });
    h += '<div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:8px">' + Object.entries(by).map(([k, v]) => '<span class="chip static"><span class="dot" style="background:' + esc(v.color) + '"></span>' + esc(k) + ' <b>' + v.n + '</b></span>').join('') + '</div>';
    h += '<table class="conn"><tr><th>Class</th><th>Client → server</th><th>Process</th></tr>' + cs.map(connRow).join('') + '</table>';
  } else h += '<p class="muted">No TCP/UDP flows between hosts right now. Try for example:<br><span class="mono">h4 iperf -s &amp;</span> then <span class="mono">h1 iperf -c 10.0.20.10 -t 30</span><br>or <span class="mono">h6 python3 -m http.server 80 &amp;</span> then <span class="mono">h5 curl 10.0.20.12</span>.</p>';
  const top = topo.links.map(l => ({l, s:live.links[l.id] || {}})).filter(x => x.s.bps > 1000).sort((a, b) => b.s.bps - a.s.bps).slice(0, 8);
  h += '<h3>Busiest links</h3>' + (top.length ? '<table>' + top.map(x => '<tr><td>' + esc(x.l.a) + ' ⇄ ' + esc(x.l.b) + '</td><td class="num">' + fmtRate(x.s.bps) + '</td></tr>').join('') + '</table>' : '<p class="muted" style="margin:0">All links idle.</p>');
  h += '<h3>Traffic classes</h3><div style="display:flex;gap:5px;flex-wrap:wrap">' + live.classes.map(c => '<span class="chip static"><span class="dot" style="background:' + esc(c.color) + '"></span>' + esc(c.name) + '</span>').join('') + '</div>';
  h += '<p class="muted">Flows come from each host\u2019s socket table (ss), so ICMP is not listed. Link throughput comes from interface counters and includes all traffic.</p>';
  el.innerHTML = h;
}
function renderEvents(){
  const el = $('#evList');
  el.innerHTML = events.slice().reverse().map(e => '<div class="ev ' + esc(e.level) + '"><time>' + fmtTime(e.t) + '</time><span class="t">' + esc(e.text) + '</span></div>').join('') || '<p class="muted">No events yet.</p>';
}
$('#btnClearEv').addEventListener('click', () => { events = []; renderEvents(); });

// ------------------------------------------------------------ tests
function populateHostSelects(){
  const hosts = topo.nodes.filter(n => n.type === 'host').map(n => n.id).sort(natural);
  for (const id of ['#pSrc', '#pDst']){
    const s = $(id), cur = s.value;
    s.innerHTML = hosts.map(h => '<option>' + esc(h) + '</option>').join('');
    if (hosts.includes(cur)) s.value = cur;
  }
  if ($('#pSrc').value === $('#pDst').value && hosts.length > 1) $('#pDst').value = hosts[1];
  updateIpSelect();
}
function updateIpSelect(){
  const s = $('#pIp'), cur = s.value, dst = $('#pDst').value;
  const addrs = ((live && live.nodes[dst] && live.nodes[dst].addrs) || []).filter(a => a.fam === 'inet');
  const opts = '<option value="">primary address</option>' + addrs.map(a => '<option value="' + esc(a.ip) + '">' + esc(a.ip) + ' (' + esc(a.iface) + (a.tunnel ? ', tunnel' : '') + ')</option>').join('');
  if (s.dataset.opts !== opts){ s.innerHTML = opts; s.dataset.opts = opts; if (addrs.some(a => a.ip === cur)) s.value = cur; }
}
$('#pDst').addEventListener('change', updateIpSelect);
function pathLinks(path){
  const out = []; if (!path) return out;
  for (let i = 1; i < path.length; i++){ const e = (adj[path[i-1]] || []).find(x => x.to === path[i]); if (e) out.push(e.link); }
  return out;
}
function animatePing(src, dst, ok, tunnel){
  const pts = routePts(src, dst, tunnel);
  const p = tunnel ? null : bfsPath(src, dst);
  anims.push({pts:pts || [pos[src], pos[dst]], ok, t0:performance.now(), dur:1400, links:pathLinks(p)});
}
async function runPing(src, dst, ip, count){
  const out = $('#pingOut'), btn = $('#btnPing');
  if (!src || !dst || src === dst){ out.textContent = 'Choose two different hosts.'; return; }
  out.classList.remove('muted'); out.textContent = 'Pinging ' + dst + ' from ' + src + '…'; btn.disabled = true;
  try {
    const r = await api('/api/ping', {src, dst, ip:ip || null, count});
    out.textContent = r.output; animatePing(src, dst, r.ok, r.tunnel);
  } catch(e){ out.textContent = 'Error: ' + e.message; }
  finally { btn.disabled = false; }
}
$('#btnPing').addEventListener('click', () => runPing($('#pSrc').value, $('#pDst').value, $('#pIp').value, +$('#pCount').value || 3));
$('#btnMatrix').addEventListener('click', async () => {
  const btn = $('#btnMatrix'), out = $('#matrixOut');
  btn.disabled = true; out.innerHTML = '<p class="muted">Running pings…</p>';
  try { lastMatrix = await api('/api/matrix', {}); renderMatrix(); }
  catch(e){ out.innerHTML = '<p class="down">Error: ' + esc(e.message) + '</p>'; }
  finally { btn.disabled = false; }
});
function renderMatrix(){
  const m = lastMatrix, out = $('#matrixOut'); if (!m) return;
  let h = '<p style="margin:0 0 6px"><b>' + m.reachable + '/' + m.total + '</b> pairs reachable. Rows = source, columns = destination.</p><table class="matrix"><tr><th></th>' + m.hosts.map(h2 => '<th>' + esc(h2) + '</th>').join('') + '</tr>';
  m.hosts.forEach(a => {
    h += '<tr><th>' + esc(a) + '</th>';
    m.hosts.forEach(b => {
      if (a === b) h += '<td class="self"></td>';
      else { const v = m.matrix[a] && m.matrix[a][b]; h += v === undefined ? '<td>–</td>' : '<td class="' + (v ? 'y' : 'n') + '" data-a="' + esc(a) + '" data-b="' + esc(b) + '" title="' + esc(a) + ' → ' + esc(b) + ' (' + esc(m.targets[b] || '') + ')">' + (v ? '✓' : '✗') + '</td>'; }
    });
    h += '</tr>';
  });
  out.innerHTML = h + '</table>';
  out.querySelectorAll('td[data-a]').forEach(td => td.addEventListener('click', () => animatePing(td.dataset.a, td.dataset.b, td.classList.contains('y'), null)));
}

// ------------------------------------------------------------ toolbar
function bindToggle(id, key){ const el = $(id); el.checked = !!settings[key]; el.addEventListener('change', () => { settings[key] = el.checked; saveSettings(); renderLegend(); }); }
bindToggle('#tIntf', 'intf'); bindToggle('#tTraffic', 'traffic'); bindToggle('#tTunnels', 'tunnels'); bindToggle('#tControl', 'control'); bindToggle('#tRates', 'rates');
$('#colorBy').value = settings.colorBy;
$('#colorBy').addEventListener('change', e => { settings.colorBy = e.target.value; focusGroup = null; saveSettings(); renderLegend(); renderDetails(); });
$('#btnTree').addEventListener('click', () => { force = null; treeLayout(); fitView(); saveLayout(); pathCache = {}; });
$('#btnForce').addEventListener('click', () => { startForce(); setTimeout(fitView, 2600); });
$('#btnFit').addEventListener('click', fitView);
$('#btnTheme').addEventListener('click', () => { settings.theme = {auto:'light', light:'dark', dark:'auto'}[settings.theme] || 'auto'; saveSettings(); applyTheme(); renderLegend(); });
$('#btnPng').addEventListener('click', () => {
  const a = document.createElement('a'); a.download = 'mininet-topology.png'; a.href = cv.toDataURL('image/png'); a.click();
});
$('#btnSave').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify({version:2, sig:topo.sig, positions:pos, view}, null, 2)], {type:'application/json'});
  const a = document.createElement('a'); a.download = 'mininet-layout.json'; a.href = URL.createObjectURL(blob); a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
});
$('#btnLoad').addEventListener('click', () => $('#fileLoad').click());
$('#fileLoad').addEventListener('change', async e => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const d = JSON.parse(await f.text()); let n = 0;
    for (const [id, p] of Object.entries(d.positions || {})) if (nodeById[id] && isFinite(p.x) && isFinite(p.y)){ pos[id] = {x:+p.x, y:+p.y}; n++; }
    if (d.view && isFinite(d.view.k)) view = {x:+d.view.x, y:+d.view.y, k:+d.view.k}; else fitView();
    force = null; pathCache = {}; saveLayout();
    $('#status').textContent = 'loaded ' + n + ' positions';
  } catch(err){ alert('Could not read layout file: ' + err.message); }
  e.target.value = '';
});

// ------------------------------------------------------------ polling
function setStatus(ok, msg){
  const s = $('#status'); s.className = 'pill ' + (ok ? 'ok' : 'bad');
  s.textContent = ok ? 'live · ' + new Date().toLocaleTimeString() : ('offline' + (msg ? ': ' + msg : ''));
}
async function poll(){
  try {
    const s = await api('/api/state?since=' + lastSeq);
    if (!topo.sig || s.sig !== topo.sig) await loadTopology();
    const prevLinks = live ? live.links : {};
    live = s; lastSeq = s.seq;
    if (Object.keys(prevLinks).some(k => prevLinks[k].up !== (s.links[k] || {}).up)) pathCache = {};
    rebuildIndex();
    const now = performance.now();
    for (const [id, n] of Object.entries(s.nodes)) if (n.dropDelta > 0) flashes[id] = now + 2500;
    if (s.events.length){
      events = events.concat(s.events).slice(-400);
      if (activeTab() !== 'events'){ unseenEv += s.events.length; $('#evBadge').textContent = unseenEv > 99 ? '99+' : unseenEv; }
      renderEvents();
    }
    const nw = s.warnings.filter(w => w.level !== 'info').length;
    $('#warnBadge').textContent = nw || '';
    $('#flowBadge').textContent = s.connections.length || '';
    setStatus(true);
    renderLegend(); renderDetails(); renderTraffic(); updateIpSelect();
  } catch(e){ setStatus(false, e.message); }
  finally { setTimeout(poll, 2000); }
}

applyTheme();
resize();
requestAnimationFrame(draw);
loadTopology().then(() => { fitView(); renderDetails(); }).catch(e => setStatus(false, e.message)).finally(poll);
})();
</script>
</body>
</html>
'''


# ---------------------------------------------------------------------------
# Standalone
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    print('This module is imported by a Mininet topology script.')
    print('\nExample:')
    print('  from gui import start_visualizer')
    print('  net = Mininet(...)')
    print('  net.start()')
    print('  start_visualizer(net)          # then open http://localhost:9090')
    print('  CLI(net)')
