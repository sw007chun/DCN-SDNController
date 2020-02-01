# Software Defined Networking(SDN) Project

1. A layer-3 routing application that installs rules in SDN switches to forward the traffice to hosts using the shortest, valid path through the network. This application logic manages the efficient switching of packets among host in a large LAN with multiple switches and potential loops.
It is an SDN controller application that wil lcompute and install shortest path routes among all the hosts in the network.

2. A distributed load balancer application that redirect new TCP connections to hosts in a round-robing manner.

This codes needs an emulated network inside of a single Linux Virtual Machine. It uses the Mininet network emulator, which is designed to emulate arbitrary topologies of emulated OpenFlow switches and Linus hosts.
