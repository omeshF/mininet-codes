#!/usr/bin/env python
"""
VLAN Segmented Network with GUI Visualizer
Usage: sudo mn --custom vlan.py --topo mytopo
"""

import sys
import os

# Add multiple potential paths to ensure gui.py can be found
potential_paths = [
    '/home/student/QA',
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
from mininet.node import Node, RemoteController, Controller
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# Import visualizer
try:
    from gui import start_visualizer
    info('*** GUI visualizer loaded successfully\n')
    VISUALIZER_AVAILABLE = True
except ImportError as e:
    info('*** GUI import error: {}\n'.format(str(e)))
    VISUALIZER_AVAILABLE = False

class MyTopo(Topo):  
    "VLAN Segmented topology with multiple departments."
    
    def __init__(self):
        "Create custom topo with VLAN segmentation."

        # Initialize topology
        Topo.__init__(self)

        # Add hosts and switches with VLAN assignments
        # Engineering Department (VLAN 10)
        Host1 = self.addHost('h1', ip='10.0.10.10/24')  # Engineering Workstation 1
        Host2 = self.addHost('h2', ip='10.0.10.11/24')  # Engineering Workstation 2
        Host3 = self.addHost('h3', ip='10.0.10.12/24')  # Engineering Server
        
        # Marketing Department (VLAN 20)  
        Host4 = self.addHost('h4', ip='10.0.20.10/24')  # Marketing Workstation 1
        Host5 = self.addHost('h5', ip='10.0.20.11/24')  # Marketing Workstation 2
        Host6 = self.addHost('h6', ip='10.0.20.12/24')  # Marketing Server
        
        # Guest Network (VLAN 30)
        Host7 = self.addHost('h7', ip='10.0.30.10/24')  # Guest Device
        
        # Add switches
        Switch1 = self.addSwitch('s1')  # Engineering Access Switch
        Switch2 = self.addSwitch('s2')  # Distribution Switch 1
        Switch3 = self.addSwitch('s3')  # Core Switch
        Switch4 = self.addSwitch('s4')  # Distribution Switch 2
        Switch5 = self.addSwitch('s5')  # Marketing Access Switch
        Switch6 = self.addSwitch('s6')  # Guest Access Switch
        
        # Add links 
        # Engineering VLAN (10) connections
        self.addLink(Host1, Switch1)
        self.addLink(Host2, Switch1)
        self.addLink(Host3, Switch1)
        
        # Trunk links between switches
        self.addLink(Switch1, Switch2)  # Engineering to Distribution
        self.addLink(Switch2, Switch3)  # Distribution to Core
        self.addLink(Switch3, Switch4)  # Core to Distribution
        self.addLink(Switch4, Switch5)  # Distribution to Marketing
        self.addLink(Switch5, Switch6)  # Marketing to Guest
        
        # Marketing VLAN (20) connections
        self.addLink(Host4, Switch5)
        self.addLink(Host5, Switch5)
        self.addLink(Host6, Switch5)
        
        # Guest VLAN (30) connection
        self.addLink(Host7, Switch6)


def setup_vlan_network(net):
    """Configure VLANs on the network switches"""
    info('\n' + '='*70 + '\n')
    info('VLAN NETWORK CONFIGURATION\n')
    info('='*70 + '\n')
    
    # Get switches
    s1, s2, s3, s4, s5, s6 = net.get('s1', 's2', 's3', 's4', 's5', 's6')
    
    print("Configuring VLANs on all switches...")
    
    # Configure VLANs on Switch1 (Engineering Access)
    print("Configuring Switch1 (Engineering Access) - VLAN 10")
    s1.cmd('ovs-vsctl set port s1-eth1 tag=10')  # h1 - Engineering
    s1.cmd('ovs-vsctl set port s1-eth2 tag=10')  # h2 - Engineering  
    s1.cmd('ovs-vsctl set port s1-eth3 tag=10')  # h3 - Engineering Server
    s1.cmd('ovs-vsctl set port s1-eth4 trunk=10')  # Trunk to Switch2
    
    # Configure VLANs on Switch2 (Distribution 1)
    print("Configuring Switch2 (Distribution 1) - Trunk ports")
    s2.cmd('ovs-vsctl set port s2-eth1 trunk=10,20,30')  # Trunk from Switch1
    s2.cmd('ovs-vsctl set port s2-eth2 trunk=10,20,30')  # Trunk to Switch3
    
    # Configure VLANs on Switch3 (Core)
    print("Configuring Switch3 (Core) - Trunk ports")  
    s3.cmd('ovs-vsctl set port s3-eth1 trunk=10,20,30')  # Trunk from Switch2
    s3.cmd('ovs-vsctl set port s3-eth2 trunk=10,20,30')  # Trunk to Switch4
    
    # Configure VLANs on Switch4 (Distribution 2)
    print("Configuring Switch4 (Distribution 2) - Trunk ports")
    s4.cmd('ovs-vsctl set port s4-eth1 trunk=10,20,30')  # Trunk from Switch3
    s4.cmd('ovs-vsctl set port s4-eth2 trunk=10,20,30')  # Trunk to Switch5
    
    # Configure VLANs on Switch5 (Marketing Access)
    print("Configuring Switch5 (Marketing Access) - VLAN 20")
    s5.cmd('ovs-vsctl set port s5-eth1 trunk=10,20,30')  # Trunk from Switch4
    s5.cmd('ovs-vsctl set port s5-eth2 tag=20')  # h4 - Marketing
    s5.cmd('ovs-vsctl set port s5-eth3 tag=20')  # h5 - Marketing
    s5.cmd('ovs-vsctl set port s5-eth4 tag=20')  # h6 - Marketing Server
    s5.cmd('ovs-vsctl set port s5-eth5 trunk=10,20,30')  # Trunk to Switch6
    
    # Configure VLANs on Switch6 (Guest Access)
    print("Configuring Switch6 (Guest Access) - VLAN 30")
    s6.cmd('ovs-vsctl set port s6-eth1 trunk=10,20,30')  # Trunk from Switch5
    s6.cmd('ovs-vsctl set port s6-eth2 tag=30')  # h7 - Guest
    
    info('\nVLAN Configuration Complete:\n')
    info('  VLAN 10: Engineering Department (h1, h2, h3)\n')
    info('  VLAN 20: Marketing Department (h4, h5, h6)\n')
    info('  VLAN 30: Guest Network (h7)\n')
    info('  Trunk ports: All inter-switch connections\n')
    info('\n' + '='*70 + '\n\n')


# Hook into Mininet's start method
import atexit

_original_start = Mininet.start

def custom_start(self):
    """Custom start that sets up VLAN after network starts."""
    result = _original_start(self)
    
    # Start visualizer if available - using port 9090 to avoid conflicts
    if VISUALIZER_AVAILABLE:
        info('\n*** Starting GUI Visualizer on port 9090...\n')
        try:
            start_visualizer(self, port=9090)
            info('*** GUI started successfully! Access at http://localhost:9090\n')
        except Exception as e:
            info('*** Failed to start visualizer: {}\n'.format(e))
            import traceback
            traceback.print_exc()
    
    setup_vlan_network(self)
    return result

Mininet.start = custom_start


def run():
    """Create and test VLAN segmented network"""
    net = Mininet(topo=MyTopo(), controller=RemoteController, waitConnected=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    net.start()
    
    setup_vlan_network(net)
    
    # Start visualizer if available
    if VISUALIZER_AVAILABLE:
        info('\n*** Starting GUI Visualizer on port 9090...\n')
        try:
            start_visualizer(net, port=9090)
            info('*** GUI started successfully! Access at http://localhost:9090\n')
        except Exception as e:
            info('*** Failed to start visualizer: {}\n'.format(e))
            import traceback
            traceback.print_exc()
    
    CLI(net)
    net.stop()


topos = {'mytopo': (lambda: MyTopo())}


if __name__ == '__main__':
    setLogLevel('info')
    run()
