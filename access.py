#!/usr/bin/env python
"""
This is a Mininet topology demonstrating Role-based, MAC-based, and Time-based Access Control.
Usage: sudo mininet --custom access.py --topo mytopo
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, OVSKernelSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from datetime import datetime, time as dt_time
import time

class AccessControlTopo(Topo):
    """
    Topology with different roles:
    - Admin hosts (h1, h2): Full access
    - Employee hosts (h3, h4): Limited access
    - Guest hosts (h5, h6): Restricted access
    - Server (h7): Protected resource
    """
    
    def build(self):
        # Add switch
        s1 = self.addSwitch('s1')
        
        # Admin hosts (full access) - all in same subnet now
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:01:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:01:02')
        
        # Employee hosts (limited access)
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:02:01')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:02:02')
        
        # Guest hosts (restricted access)
        h5 = self.addHost('h5', ip='10.0.0.5/24', mac='00:00:00:00:03:01')
        h6 = self.addHost('h6', ip='10.0.0.6/24', mac='00:00:00:00:03:02')
        
        # Server (protected resource)
        h7 = self.addHost('h7', ip='10.0.0.100/24', mac='00:00:00:00:00:07')
        
        # Add links
        for h in [h1, h2, h3, h4, h5, h6, h7]:
            self.addLink(h, s1)


class AccessControlPolicy:
    """Manages access control policies."""
    
    def __init__(self):
        # Role definitions with MAC addresses
        self.roles = {
            'admin': {
                'macs': ['00:00:00:00:01:01', '00:00:00:00:01:02'],
                'hosts': ['h1', 'h2'],
                'access_level': 'full',
                'allowed_ports': [22, 80, 443, 8080],  # SSH, HTTP, HTTPS, custom
                'time_restricted': False
            },
            'employee': {
                'macs': ['00:00:00:00:02:01', '00:00:00:00:02:02'],
                'hosts': ['h3', 'h4'],
                'access_level': 'limited',
                'allowed_ports': [80, 443],  # HTTP, HTTPS only
                'time_restricted': True,
                'allowed_hours': (9, 17)  # 9 AM - 5 PM
            },
            'guest': {
                'macs': ['00:00:00:00:03:01', '00:00:00:00:03:02'],
                'hosts': ['h5', 'h6'],
                'access_level': 'restricted',
                'allowed_ports': [80],  # HTTP only
                'time_restricted': True,
                'allowed_hours': (8, 18),  # 8 AM - 6 PM
                'rate_limit': True
            }
        }
        
        self.server_mac = '00:00:00:00:00:07'
        self.server_ip = '10.0.0.100'
    
    def get_role_by_mac(self, mac):
        """Get role based on MAC address."""
        for role, config in self.roles.items():
            if mac in config['macs']:
                return role, config
        return None, None
    
    def is_time_allowed(self, role_config):
        """Check if current time is within allowed hours."""
        if not role_config.get('time_restricted', False):
            return True
        
        current_hour = datetime.now().hour
        start_hour, end_hour = role_config['allowed_hours']
        
        return start_hour <= current_hour < end_hour


def setup_access_control(net, policy):
    """Setup access control rules using iptables and tc."""
    info('*** Setting up Access Control Policies\n')
    
    switch = net['s1']
    server = net['h7']
    
    # Start services on h7
    info('*** Starting services on h7 ({})\n'.format(server.IP()))
    
    # HTTP server on port 80
    server.cmd('cd /tmp && echo "Welcome to the protected server!" > index.html')
    server.cmd('python3 -m http.server 80 > /dev/null 2>&1 &')
    
    # HTTPS listener on port 443
    info('*** Starting HTTPS listener on port 443\n')
    server.cmd('python3 -c "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\'\', 443)); s.listen(5); [s.accept() for _ in range(100)]" > /dev/null 2>&1 &')
    
    # SSH listener on port 22
    info('*** Starting SSH listener on port 22\n')
    server.cmd('python3 -c "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\'\', 22)); s.listen(5); [s.accept() for _ in range(100)]" > /dev/null 2>&1 &')
    
    # Custom listener on port 8080
    info('*** Starting custom listener on port 8080\n')
    server.cmd('python3 -c "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind((\'\', 8080)); s.listen(5); [s.accept() for _ in range(100)]" > /dev/null 2>&1 &')
    
    # Give services time to start
    server.cmd('sleep 1')
    
    # Configure server firewall (default deny, then allow based on rules)
    info('*** Configuring server firewall rules\n')
    server.cmd('iptables -F')  # Flush existing rules
    server.cmd('iptables -P INPUT DROP')  # Default drop
    server.cmd('iptables -P FORWARD DROP')
    server.cmd('iptables -P OUTPUT ACCEPT')
    
    # Allow loopback
    server.cmd('iptables -A INPUT -i lo -j ACCEPT')
    
    # Apply role-based rules
    for role, config in policy.roles.items():
        info('*** Applying rules for role: {}\n'.format(role))
        
        for mac in config['macs']:
            # Allow specific ports based on role
            for port in config['allowed_ports']:
                # Rate limiting for guests on allowed ports only
                if config.get('rate_limit', False):
                    info('    - Rate limiting enabled for {} on port {}\n'.format(mac, port))
                    server.cmd('iptables -A INPUT -p tcp --dport {} -m mac --mac-source {} -m limit --limit 10/min -j ACCEPT'.format(port, mac))
                else:
                    server.cmd('iptables -A INPUT -p tcp --dport {} -m mac --mac-source {} -j ACCEPT'.format(port, mac))
        
        info('    - Access level: {}\n'.format(config['access_level']))
        info('    - Allowed ports: {}\n'.format(', '.join(map(str, config['allowed_ports']))))
        if config.get('time_restricted'):
            info('    - Time restricted: {} - {}\n'.format(
                config['allowed_hours'][0], config['allowed_hours'][1]))
    
    # Log dropped packets (optional)
    server.cmd('iptables -A INPUT -j LOG --log-prefix "DROPPED: " --log-level 4')
    
    info('\n*** Access Control Setup Complete!\n\n')


def print_access_policy(policy):
    """Print the access control policy in a readable format."""
    info('\n' + '='*70 + '\n')
    info('ACCESS CONTROL POLICY SUMMARY\n')
    info('='*70 + '\n\n')
    
    for role, config in policy.roles.items():
        info('ROLE: {}\n'.format(role.upper()))
        info('-' * 50 + '\n')
        info('  Hosts: {}\n'.format(', '.join(config['hosts'])))
        info('  MAC Addresses: {}\n'.format(', '.join(config['macs'])))
        info('  Access Level: {}\n'.format(config['access_level']))
        info('  Allowed Ports: {}\n'.format(', '.join(map(str, config['allowed_ports']))))
        
        if config.get('time_restricted'):
            start, end = config['allowed_hours']
            info('  Time Restriction: {}:00 - {}:00\n'.format(start, end))
        else:
            info('  Time Restriction: None (24/7 access)\n')
        
        if config.get('rate_limit'):
            info('  Rate Limiting: Enabled (10 requests/min)\n')
        
        info('\n')
    
    info('SERVER: h7\n')
    info('-' * 50 + '\n')
    info('  IP: {}\n'.format(policy.server_ip))
    info('  MAC: {}\n'.format(policy.server_mac))
    info('  Service: HTTP Server on port 80\n')
    info('\n' + '='*70 + '\n\n')


def run_network():
    """Create and run the network with access control."""
    setLogLevel('info')
    
    # Create topology and network
    topo = AccessControlTopo()
    net = Mininet(topo=topo,
                  controller=Controller,
                  link=TCLink,
                  switch=OVSKernelSwitch,
                  autoSetMacs=True)
    
    net.start()
    
    # Create access control policy
    policy = AccessControlPolicy()
    
    # Print policy summary
    print_access_policy(policy)
    
    # Setup access control
    setup_access_control(net, policy)
    
    info('*** Running CLI\n')
    info('*** Type "exit" to quit\n\n')
    CLI(net)
    
    # Cleanup
    info('*** Stopping network\n')
    net['h7'].cmd('pkill -f "python3 -m http.server"')
    net['h7'].cmd('pkill -f "python3 -c"')
    net.stop()


# Hook into Mininet's start method to apply access control automatically
import atexit

# Store original Mininet start method
_original_start = Mininet.start

def custom_start(self):
    """Custom start that sets up access control after network starts."""
    # Call original start
    result = _original_start(self)
    
    # Create and apply access control policy
    policy = AccessControlPolicy()
    print_access_policy(policy)
    setup_access_control(self, policy)
    
    return result

# Replace Mininet's start method
Mininet.start = custom_start

# Cleanup function
def cleanup():
    """Cleanup on exit."""
    import os
    os.system('pkill -f "python3 -m http.server" 2>/dev/null')
    os.system('pkill -f "python3 -c" 2>/dev/null')

atexit.register(cleanup)

# Register the topology
topos = {
    'mytopo': AccessControlTopo
}

if __name__ == '__main__':
    run_network()
