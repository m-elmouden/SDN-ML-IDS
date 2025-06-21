from mininet.net import Mininet
from mininet.node import Controller, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.clean import cleanup
import time

def createNetwork():
    # Clean up any leftover Mininet state
    cleanup()
    
    # Create a network with remote controller
    net = Mininet(controller=None)  # Start without controller, we'll add it manually
   
    # Add controller
    info("*** Adding controller\n")
    # Try connecting to the Ryu controller using the container name and the correct port
    c0 = net.addController(name="c0", controller=RemoteController, ip="ryu-controller-15", port=6653)
   
    # Add hosts
    info("*** Adding hosts\n")
    h1 = net.addHost("h1", ip="172.18.0.101/16")
    h2 = net.addHost("h2", ip="172.18.0.102/16")
    h3 = net.addHost("h3", ip="172.18.0.103/16")
    h4 = net.addHost("h4", ip="172.18.0.104/16")
   
    # Add switch
    info("*** Adding switch\n")
    s1 = net.addSwitch("s1")
   
    # Create links
    info("*** Creating links\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h4, s1)
   
    # Start network
    info("*** Starting network\n")
    net.build()
    
    # Start controller
    info("*** Starting controller\n")
    c0.start()
    
    # Start switches
    info("*** Starting switches\n")
    s1.start([c0])
    
    # Give some time for the controller to connect
    info("*** Waiting for controller connection\n")
    time.sleep(3)
   
    # Add some useful test commands
    info("*** Running test commands\n")
    
    # Check switch connection to controller first
    info("*** Checking switch connection to controller\n")
    output = s1.cmd("ovs-vsctl show")
    info(output)
    
    if "is_connected: true" in output:
        info("*** Controller connection successful!\n")
    else:
        info("*** WARNING: Controller doesn't seem to be connected. Check controller IP and port.\n")
    
    info("*** Testing connectivity between hosts\n")
    net.pingAll()
    
    # Run CLI
    info("*** Running CLI\n")
    CLI(net)
   
    # Stop network
    info("*** Stopping network\n")
    net.stop()

if __name__ == "__main__":
    setLogLevel("info")
    createNetwork()
