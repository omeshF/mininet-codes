#!/usr/bin/env python
"""
VPN demonstration using GRE tunnels with IPsec encryption.
Usage: sudo mn --custom vpn.py --topo mytopo

This demonstrates a production-like VPN using:
- GRE tunnel for connectivity
- IPsec (ESP) for encryption and authentication
- Web-based GUI visualizer
"""

import sys
import os

# Add multiple potential paths to ensure gui.py can be found
potential_paths = [
    '/home/qa/cssi',
]

# Try to add the directory of the current script if __file__ is available
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in potential_paths:
        potential_paths.append(script_dir)
except NameError:
    # __file__ is not available, which is fine
    pass

# Add current working directory
current_dir = os.getcwd()
if current_dir not in potential_paths:
    potential_paths.append(current_dir)

for path in potential_paths:
    if path and path not in sys.path:
        sys.path.insert(0, path)


from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
import time

# Import visualizer without try-catch to see the error
try:
    from gui import start_visualizer
    info('*** GUI visualizer loaded successfully\n')
    VISUALIZER_AVAILABLE = True
except ImportError as e:
    info('*** GUI import error: {}\n'.format(str(e)))
    VISUALIZER_AVAILABLE = False

class VPNTopo(Topo):
    """
    Topology with two separate networks connected via VPN tunnel:
    - Main Network: 10.0.0.0/24
    - Remote Network: 192.168.10.0/24
    - VPN Tunnel: 10.10.10.0/24
    """
    
    def build(self):
        # Create switches for different networks
        remote_net = self.addSwitch('s1')
        main_net = self.addSwitch('s2')
        internet = self.addSwitch('s3')
        
        # Remote network hosts
        remote_host = self.addHost('remote', ip='192.168.10.10/24')
        remote_gw = self.addHost('remote_gw', ip=None)
        
        # Main network hosts
        main_host = self.addHost('main', ip='10.0.0.10/24')
        main_gw = self.addHost('main_gw', ip=None)
        
        # Remote network connections
        self.addLink(remote_host, remote_net)
        self.addLink(remote_gw, remote_net)
        self.addLink(remote_gw, internet)
        
        # Main network connections
        self.addLink(main_host, main_net)
        self.addLink(main_gw, main_net)
        self.addLink(main_gw, internet)


def setup_vpn_tunnel(net):
    """Configure GRE tunnel (simulated VPN) between networks."""
    
    info('\n' + '='*70 + '\n')
    info('VPN TUNNEL SETUP (GRE + IPsec Encryption)\n')
    info('='*70 + '\n\n')
    
    remote_host = net['remote']
    remote_gw = net['remote_gw']
    main_host = net['main']
    main_gw = net['main_gw']
    
    info('*** Configuring network interfaces and routing...\n')
    
    # Configure remote network
    remote_gw.cmd('ip addr add 192.168.10.1/24 dev remote_gw-eth0')
    remote_gw.cmd('ip addr add 203.0.113.1/24 dev remote_gw-eth1')  # Public IP
    remote_host.cmd('ip route add default via 192.168.10.1')
    remote_gw.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null')
    
    # Configure main network
    main_gw.cmd('ip addr add 10.0.0.1/24 dev main_gw-eth0')
    main_gw.cmd('ip addr add 203.0.113.2/24 dev main_gw-eth1')  # Public IP in same subnet!
    main_host.cmd('ip route add default via 10.0.0.1')
    main_gw.cmd('sysctl -w net.ipv4.ip_forward=1 > /dev/null')
    
    info('*** Creating GRE tunnel (simulated VPN)...\n')
    
    # Create GRE tunnel on main gateway (use gre1 instead of gre0)
    main_gw.cmd('ip tunnel add gre1 mode gre remote 203.0.113.1 local 203.0.113.2 ttl 255')
    main_gw.cmd('ip addr add 10.10.10.1/30 dev gre1')
    main_gw.cmd('ip link set gre1 up')
    
    # Create GRE tunnel on remote gateway
    remote_gw.cmd('ip tunnel add gre1 mode gre remote 203.0.113.2 local 203.0.113.1 ttl 255')
    remote_gw.cmd('ip addr add 10.10.10.2/30 dev gre1')
    remote_gw.cmd('ip link set gre1 up')
    
    info('*** Adding IPsec encryption over GRE tunnel...\n')
    
    # Pre-shared key for IPsec (need proper length for AES-128: 16 bytes = 32 hex chars)
    psk = "0123456789abcdef0123456789abcdef"  # 32 hex characters
    auth_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"  # 64 hex for SHA256
    
    # Configure IPsec on main gateway
    main_gw.cmd('ip xfrm state add src 203.0.113.2 dst 203.0.113.1 proto esp spi 0x200 mode transport auth sha256 0x{} enc aes 0x{}'.format(auth_key, psk))
    main_gw.cmd('ip xfrm state add src 203.0.113.1 dst 203.0.113.2 proto esp spi 0x100 mode transport auth sha256 0x{} enc aes 0x{}'.format(auth_key, psk))
    main_gw.cmd('ip xfrm policy add src 203.0.113.2 dst 203.0.113.1 dir out tmpl src 203.0.113.2 dst 203.0.113.1 proto esp mode transport')
    main_gw.cmd('ip xfrm policy add src 203.0.113.1 dst 203.0.113.2 dir in tmpl src 203.0.113.1 dst 203.0.113.2 proto esp mode transport')
    
    # Configure IPsec on remote gateway
    remote_gw.cmd('ip xfrm state add src 203.0.113.1 dst 203.0.113.2 proto esp spi 0x100 mode transport auth sha256 0x{} enc aes 0x{}'.format(auth_key, psk))
    remote_gw.cmd('ip xfrm state add src 203.0.113.2 dst 203.0.113.1 proto esp spi 0x200 mode transport auth sha256 0x{} enc aes 0x{}'.format(auth_key, psk))
    remote_gw.cmd('ip xfrm policy add src 203.0.113.1 dst 203.0.113.2 dir out tmpl src 203.0.113.1 dst 203.0.113.2 proto esp mode transport')
    remote_gw.cmd('ip xfrm policy add src 203.0.113.2 dst 203.0.113.1 dir in tmpl src 203.0.113.2 dst 203.0.113.1 proto esp mode transport')
    
    info('    ✓ IPsec encryption enabled (AES-128 + SHA256)\n')
    info('    ✓ All GRE traffic is now encrypted\n')
    
    info('*** Configuring routes through VPN tunnel...\n')
    
    # Add routes through tunnel
    main_gw.cmd('ip route add 192.168.10.0/24 via 10.10.10.2 dev gre1')
    remote_gw.cmd('ip route add 10.0.0.0/24 via 10.10.10.1 dev gre1')
    
    info('\n' + '='*70 + '\n')
    info('VPN TUNNEL CONFIGURATION COMPLETE\n')
    info('='*70 + '\n\n')
    
    info('Network Configuration:\n')
    info('  Main Network:    10.0.0.0/24\n')
    info('    - main:        10.0.0.10\n')
    info('    - main_gw:     10.0.0.1 (Public IP: 203.0.113.2)\n')
    info('\n')
    info('  Remote Network:  192.168.10.0/24\n')
    info('    - remote:      192.168.10.10\n')
    info('    - remote_gw:   192.168.10.1 (Public IP: 203.0.113.1)\n')
    info('\n')
    info('  VPN Tunnel:      10.10.10.0/30 (GRE tunnel)\n')
    info('    - main_gw:     10.10.10.1\n')
    info('    - remote_gw:   10.10.10.2\n')
    info('    - Encryption:  IPsec ESP (AES-128 + SHA256)\n')
    info('\n')
    
    # Test VPN connectivity
    info('*** Testing VPN tunnel connectivity...\n')
    
    info('  Testing tunnel endpoints...')
    result = main_gw.cmd('ping -c 1 -W 2 10.10.10.2 2>&1')
    if '1 packets transmitted, 1 received' in result or '1 received' in result:
        info(' ✓ Tunnel is UP!\n')
    else:
        info(' ✗ Tunnel failed\n')
    
    info('  Testing cross-network connectivity...')
    result = remote_host.cmd('ping -c 1 -W 2 10.0.0.10 2>&1')
    if '1 packets transmitted, 1 received' in result or '1 received' in result:
        info(' ✓ Success!\n')
    else:
        info(' ✗ Failed\n')
        info('     Debug: {}\n'.format(result[:100] if result else 'No response'))
    
    result = main_host.cmd('ping -c 1 -W 2 192.168.10.10 2>&1')
    if '1 packets transmitted, 1 received' in result or '1 received' in result:
        info(' ✓ Success!\n')
    else:
        info(' ✗ Failed\n')
        info('     Debug: {}\n'.format(result[:100] if result else 'No response'))
    
    info('\n')


# Hook into Mininet's start method
import atexit

_original_start = Mininet.start

def custom_start(self):
    """Custom start that sets up VPN after network starts."""
    result = _original_start(self)
    
    # Start visualizer if available
    if VISUALIZER_AVAILABLE:
        info('\n*** Starting GUI Visualizer...\n')
        try:
            start_visualizer(self, port=9090)
            info('*** GUI started successfully!\n')
        except Exception as e:
            info('*** Failed to start visualizer: {}\n'.format(e))
            import traceback
            traceback.print_exc()
    
    setup_vpn_tunnel(self)
    return result

Mininet.start = custom_start

# Cleanup function
def cleanup():
    """Cleanup on exit."""
    import os
    os.system('ip xfrm state flush 2>/dev/null')
    os.system('ip xfrm policy flush 2>/dev/null')
    os.system('ip tunnel del gre1 2>/dev/null')

atexit.register(cleanup)

# Register the topology
topos = {
    'mytopo': VPNTopo
}


def run_network():
    """Create and run the network directly."""
    setLogLevel('info')
    
    topo = VPNTopo()
    net = Mininet(topo=topo,
                  controller=Controller,
                  link=TCLink,
                  switch=OVSSwitch,
                  autoSetMacs=True)
    
    net.start()
    
    info('*** Running VPN setup\n')
    setup_vpn_tunnel(net)
    
    # Start visualizer if available
    if VISUALIZER_AVAILABLE:
        info('\n*** Starting GUI Visualizer...\n')
        try:
            start_visualizer(net, port=9090)
            info('*** GUI started successfully!\n')
        except Exception as e:
            info('*** Failed to start visualizer: {}\n'.format(e))
            import traceback
            traceback.print_exc()
    
    info('*** Running CLI\n')
    info('*** Type "exit" to quit\n\n')
    CLI(net)
    
    # Cleanup
    info('*** Stopping network\n')
    net['main_gw'].cmd('ip xfrm state flush 2>/dev/null')
    net['main_gw'].cmd('ip xfrm policy flush 2>/dev/null')
    net['remote_gw'].cmd('ip xfrm state flush 2>/dev/null')
    net['remote_gw'].cmd('ip xfrm policy flush 2>/dev/null')
    net['main_gw'].cmd('ip tunnel del gre1 2>/dev/null')
    net['remote_gw'].cmd('ip tunnel del gre1 2>/dev/null')
    net.stop()

if __name__ == '__main__':
    run_network()
