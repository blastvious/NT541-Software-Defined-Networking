"""
Author: Nguyen Anh Tuan MSSV: 23521717
Topology for DoS Detection Project
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from functools import partial

class DoS_Topo(Topo):
    "2 Switches, 4 Hosts Topology for DoS Project"
    def build(self):
        # 1. Create Open vSwitch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # 2. Create 4 Host
        h1 = self.addHost('h1') # Attacker
        h2 = self.addHost('h2') # Normal Client 1
        h3 = self.addHost('h3') # Normal Client 2
        h4 = self.addHost('h4') # Web Server (Victim)

        # 3. Limit bandwith (100 Mbps)
        # Connection linking
        self.addLink(s1, s2, bw=100)
        
        
        self.addLink(h1, s1, bw=100)
        self.addLink(h2, s1, bw=100)
        self.addLink(h3, s1, bw=100)
        
        
        self.addLink(h4, s2, bw=100)

def init_network():
    topo = DoS_Topo()
    ovs_switch = partial(OVSKernelSwitch, protocols='OpenFlow13')
    
    # Using TCLink to activate bandwith limitation  (bw)
    net = Mininet(topo=topo, switch=ovs_switch, link=TCLink, build=False)      
    
    info('Try to connect to ryu controller \n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info("Starting network\n")
    net.build()
    net.start()

    info("Running CLI\n")
    CLI(net)

    info('Clear setup before exit\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    init_network()