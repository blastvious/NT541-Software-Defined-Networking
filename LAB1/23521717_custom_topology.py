"""
Author: Nguyen Anh Tuan MSSV: 23521717
A custom topology

"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from functools import partial

class Lab_1_Topo (Topo):
    "Lab 1 topology"
    def build(self):
        # create 4 switch
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        # create 4 host
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        #Make connection between switchs
        self.addLink(s1,s2)
        self.addLink(s2,s3)
        self.addLink(s3,s4)
        #Make connection between switch and host
        self.addLink(h1,s1)
        self.addLink(h2,s2)
        self.addLink(h3,s3)
        self.addLink(h4,s4)

def init_network():
    topo = Lab_1_Topo()
    ovs_switch = partial(OVSKernelSwitch, protocols='OpenFlow13' )
    net = Mininet(topo=topo, switch=ovs_switch, build=False)      
    info('Try to connect to ryu controller \n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info("Starting network")
    net.build()
    net.start()

    info("Running CLI")
    CLI(net)

    info('Clear setup before exit\n')
    net.stop()
if __name__ == '__main__':
    setLogLevel('info')
    init_network()
    
             

