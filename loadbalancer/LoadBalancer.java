package edu.nyu.cs.sdn.apps.loadbalancer;

import edu.nyu.cs.sdn.apps.sps.InterfaceShortestPathSwitching;
import edu.nyu.cs.sdn.apps.sps.ShortestPathSwitching;
import edu.nyu.cs.sdn.apps.util.ArpServer;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;

import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionSetField;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.openflow.protocol.instruction.OFInstructionGotoTable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.IListener.Command;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.internal.DeviceManagerImpl;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.util.MACAddress;

public class LoadBalancer implements IFloodlightModule, IOFSwitchListener,
		IOFMessageListener
{
	public static final String MODULE_NAME = LoadBalancer.class.getSimpleName();
	
	private static final byte TCP_FLAG_SYN = 0x02;
	
	private static final byte TCP_FLAG_RST = 0x04;
	
	private static final short IDLE_TIMEOUT = 20;
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;
    
    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Interface to ShortestPathSwitching application
    private InterfaceShortestPathSwitching spsApp;
    
    // Switch table in which rules should be installed
    private byte table;
    
    // Set of virtual IPs and the load balancer instances they correspond with
    private Map<Integer,LoadBalancerInstance> instances;

    /**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		
		// Obtain table number from config
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
        // Create instances from config
        this.instances = new HashMap<Integer,LoadBalancerInstance>();
        String[] instanceConfigs = config.get("instances").split(";");
        for (String instanceConfig : instanceConfigs)
        {
        	String[] configItems = instanceConfig.split(" ");
        	if (configItems.length != 3)
        	{ 
        		log.error("Ignoring bad instance config: " + instanceConfig);
        		continue;
        	}
        	LoadBalancerInstance instance = new LoadBalancerInstance(
        			configItems[0], configItems[1], configItems[2].split(","));
            this.instances.put(instance.getVirtualIP(), instance);
            log.info("Added load balancer instance: " + instance);
        }
        
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        this.spsApp = context.getServiceImpl(InterfaceShortestPathSwitching.class);
        
        /*********************************************************************/
        /* TODO: Initialize other class variables, if necessary              */
        /*********************************************************************/
        
	}

	/**
     * Subscribes to events and performs other startup tasks.
     */
	@Override
	public void startUp(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Starting %s...", MODULE_NAME));
		this.floodlightProv.addOFSwitchListener(this);
		this.floodlightProv.addOFMessageListener(OFType.PACKET_IN, this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		/*********************************************************************/
	}
	
	/**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("!virtual! Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Install rules to send:                                      */
		/*       (1) packets from new connections to each virtual load       */
		/*       balancer IP to the controller                               */
		/*       (2) ARP packets to the controller, and                      */
		/*       (3) all other packets to the next rule table in the switch  */
		/*********************************************************************/
		
		
		//any tcp packet to virtual ip or arp packet will be sent to the controller		
		for(int virtualIP : instances.keySet()){
			OFMatchField ethType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
			OFMatchField fieldIP = new OFMatchField(OFOXMFieldType.IPV4_DST, virtualIP);
			
			ArrayList<OFMatchField> matchFieldsIPPackets = new ArrayList<OFMatchField>();
			matchFieldsIPPackets.add(ethType);
			matchFieldsIPPackets.add(fieldIP);
			
			OFMatch ofMatchIP = new OFMatch();
			ofMatchIP.setMatchFields(matchFieldsIPPackets);
			
			//output port to the controller
			OFActionOutput ofActionOutput = new OFActionOutput();
			ofActionOutput.setPort(OFPort.OFPP_CONTROLLER);
	
			ArrayList<OFAction> ofActions = new ArrayList <OFAction>();
			ofActions.add(ofActionOutput);
			
			OFInstructionApplyActions applyActions = new OFInstructionApplyActions(ofActions);
			ArrayList<OFInstruction> listOfInstructions = new ArrayList<OFInstruction>();
			listOfInstructions.add(applyActions);

			SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, ofMatchIP, listOfInstructions);
		}
			
		log.info(String.format("install ARP Rule"));
		
		for(int virtualIP : instances.keySet()){
			OFMatchField ethType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_ARP);
			OFMatchField fieldIP = new OFMatchField(OFOXMFieldType.IPV4_DST, virtualIP);
			
			ArrayList<OFMatchField> matchFieldsIPPackets = new ArrayList<OFMatchField>();
			matchFieldsIPPackets.add(ethType);
			matchFieldsIPPackets.add(fieldIP);
			
			OFMatch ofMatchIP = new OFMatch();
			ofMatchIP.setMatchFields(matchFieldsIPPackets);
			
			OFActionOutput ofActionOutput = new OFActionOutput();
			ofActionOutput.setPort(OFPort.OFPP_CONTROLLER);
	
			ArrayList<OFAction> ofActions = new ArrayList <OFAction>();
			ofActions.add(ofActionOutput);
			
			OFInstructionApplyActions applyActions = new OFInstructionApplyActions(ofActions);
			ArrayList<OFInstruction> listOfInstructions = new ArrayList<OFInstruction>();
			listOfInstructions.add(applyActions);

			SwitchCommands.installRule(sw, table, SwitchCommands.DEFAULT_PRIORITY, ofMatchIP, listOfInstructions);
		}
		
		//if the packet is not a tcp to virtual ip or arp packet it will check the rule of shortest distance
		
		log.info(String.format("install normal Rule"));
		
		OFMatch match = new OFMatch();
		OFInstructionGotoTable goToTable = new OFInstructionGotoTable();
		goToTable.setTableId(ShortestPathSwitching.table );
		List<OFInstruction> instructions = new ArrayList<OFInstruction>();
		instructions.add(goToTable);
		
		SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY ), match, instructions);	
		log.info("bad? " +this.table);
		
	}
	
	/**
	 * Handle incoming packets sent from switches.
	 * @param sw switch on which the packet was received
	 * @param msg message from the switch
	 * @param cntx the Floodlight context in which the message should be handled
	 * @return indication whether another module should also process the packet
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) 
	{
		// We're only interested in packet-in messages
		if (msg.getType() != OFType.PACKET_IN)
		{ return Command.CONTINUE; }
		OFPacketIn pktIn = (OFPacketIn)msg;
		
		// Handle the packet
		Ethernet ethPkt = new Ethernet();
		ethPkt.deserialize(pktIn.getPacketData(), 0, pktIn.getPacketData().length);
		
		/*********************************************************************/
		/* TODO: Send an ARP reply for ARP requests for virtual IPs; for TCP */
		/*       SYNs sent to a virtual IP, select a host and install        */
		/*       connection-specific rules to rewrite IP and MAC addresses;  */
		/*       for all other TCP packets sent to a virtual IP, send a TCP  */
		/*       reset; ignore all other  packets                             */
		/*********************************************************************/
		
//		log.info(String.format("calling controller"));
		
		if (ethPkt.getEtherType() == Ethernet.TYPE_ARP)
		{ 						
			ARP arp = (ARP)ethPkt.getPayload();
			
			// We only care about ARP requests for IPv4 addresses
			if (arp.getOpCode() != ARP.OP_REQUEST || arp.getProtocolType() != ARP.PROTO_TYPE_IP)
			{ return Command.CONTINUE; } 
					
			// See if we known about the device whose MAC address is being requested
			int targetIP = IPv4.toIPv4Address(arp.getTargetProtocolAddress());
			log.info(String.format("Received ARP request for virtual IP %s from %s",
					IPv4.fromIPv4Address(targetIP),
					MACAddress.valueOf(arp.getSenderHardwareAddress()).toString()));
			
			// Create ARP reply
			LoadBalancerInstance instance = this.instances.get(targetIP);
			if (instance == null)
			{ return Command.CONTINUE; }
			
			byte[] deviceMac = MACAddress.valueOf(instance.getVirtualMAC()).toBytes();
			arp.setOpCode(ARP.OP_REPLY);
			arp.setTargetHardwareAddress(arp.getSenderHardwareAddress());
			arp.setTargetProtocolAddress(arp.getSenderProtocolAddress());
			arp.setSenderHardwareAddress(deviceMac);
			arp.setSenderProtocolAddress(IPv4.toIPv4AddressBytes(targetIP));
			ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
			ethPkt.setSourceMACAddress(deviceMac);
			
			// Send the ARP reply
			log.info(String.format("Sending ARP reply %s->%s",
					IPv4.fromIPv4Address(targetIP),
					MACAddress.valueOf(deviceMac).toString()));
			SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethPkt);
		}
		else if (ethPkt.getEtherType() == Ethernet.TYPE_IPv4) {
			IPv4 ip = (IPv4) ethPkt.getPayload();
			if(ip.getProtocol() == IPv4.PROTOCOL_TCP)
			{
				TCP tcp = (TCP) ip.getPayload();
				log.info( "tcp_flag: " +tcp.getFlags());
				if (tcp.getFlags() == TCP_FLAG_SYN ) 
				{ 
					log.info("tcp rule");
					int virtualIP = ip.getDestinationAddress();
					LoadBalancerInstance newInstance = instances.get(ip.getDestinationAddress());
					int hostIPAddr = newInstance.getNextHostIP();
					byte[] hostMACAddr = this.getHostMACAddress(hostIPAddr);
					
					//client -> server rule
					
					//matching IPv4 and TCP
					OFMatchField c2sEthType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
					OFMatchField c2sIpType = new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP);
					
					//matching src and dst ip
					OFMatchField c2sSrcIpAddr = new OFMatchField(OFOXMFieldType.IPV4_SRC, ip.getSourceAddress());
					OFMatchField c2sDstIpAddr = new OFMatchField(OFOXMFieldType.IPV4_DST, virtualIP);
					
					//matchi src and dst port
					OFMatchField c2sSrcPort = new OFMatchField(OFOXMFieldType.TCP_SRC, tcp.getSourcePort());
					OFMatchField c2sDstPort = new OFMatchField(OFOXMFieldType.TCP_DST, tcp.getDestinationPort());

					ArrayList<OFMatchField> c2sMatchField = new ArrayList<OFMatchField>();
					c2sMatchField.add(c2sEthType);
					c2sMatchField.add(c2sIpType);
					c2sMatchField.add(c2sSrcIpAddr);
					c2sMatchField.add(c2sDstIpAddr);
					c2sMatchField.add(c2sSrcPort);
					c2sMatchField.add(c2sDstPort);
					
					OFMatch c2sMatch = new OFMatch();
					c2sMatch.setMatchFields(c2sMatchField);
					
					//actions to change to destination mac and ip address from virtual IP to real host IP and MAC
					OFActionSetField c2sMAC = new OFActionSetField(OFOXMFieldType.ETH_DST, hostMACAddr);
					OFActionSetField c2sIP = new OFActionSetField(OFOXMFieldType.IPV4_DST, hostIPAddr);
					
					List<OFAction> c2sActions = new ArrayList<OFAction>();
					c2sActions.add(c2sMAC);
					c2sActions.add(c2sIP);
					
					//after changing the destination IP it has to look up shortest path
					OFInstructionGotoTable l3Table = new OFInstructionGotoTable(ShortestPathSwitching.table);
					
					List<OFInstruction> c2sInstructions = new ArrayList<OFInstruction>();
					c2sInstructions.add(new OFInstructionApplyActions(c2sActions));
					c2sInstructions.add(l3Table);
					log.info("c2s rule");
					//setting higher priority than normal relaying tcp packets and have idle_timeout
					SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1),
							c2sMatch, c2sInstructions, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);
					
					//server -> client rule
					OFMatchField s2cEthType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
					OFMatchField s2cIpType = new OFMatchField(OFOXMFieldType.IP_PROTO, IPv4.PROTOCOL_TCP);
					
					OFMatchField s2cSrcIpAddr = new OFMatchField(OFOXMFieldType.IPV4_SRC, hostIPAddr);
					OFMatchField s2cDstIpAddr = new OFMatchField(OFOXMFieldType.IPV4_DST, ip.getSourceAddress());

					OFMatchField s2cSrcPort = new OFMatchField(OFOXMFieldType.TCP_SRC, tcp.getDestinationPort());
					OFMatchField s2cDstPort = new OFMatchField(OFOXMFieldType.TCP_DST, tcp.getSourcePort());

					ArrayList<OFMatchField> s2cMatchField = new ArrayList<OFMatchField>();
					s2cMatchField.add(s2cEthType);
					s2cMatchField.add(s2cIpType);
					s2cMatchField.add(s2cSrcIpAddr);
					s2cMatchField.add(s2cDstIpAddr);
					s2cMatchField.add(s2cSrcPort);
					s2cMatchField.add(s2cDstPort);
					
					OFMatch s2cMatch = new OFMatch();
					s2cMatch.setMatchFields(s2cMatchField);
					
					OFActionSetField s2cMAC = new OFActionSetField(OFOXMFieldType.ETH_SRC, instances.get(virtualIP).getVirtualMAC());
					OFActionSetField s2cIP = new OFActionSetField(OFOXMFieldType.IPV4_SRC, virtualIP);
					
					List<OFAction> s2cActions = new ArrayList<OFAction>();
					s2cActions.add(s2cMAC);
					s2cActions.add(s2cIP);
					
					List<OFInstruction> s2cInstructions = new ArrayList<OFInstruction>();
					s2cInstructions.add(new OFInstructionApplyActions(s2cActions));
					s2cInstructions.add(l3Table);
					log.info("s2c rule");
					//setting higher priority than normal relaying tcp packets and have idle_timeout
					SwitchCommands.installRule(sw, this.table, (short)(SwitchCommands.DEFAULT_PRIORITY + 1),
							s2cMatch, s2cInstructions, SwitchCommands.NO_TIMEOUT, IDLE_TIMEOUT);			
				}
				else
				{
					log.info("normal rule");
					ip.setFlags(TCP_FLAG_RST);
					ip.setDestinationAddress(ip.getSourceAddress());
					ip.setSourceAddress(ip.getDestinationAddress());
					ethPkt.setDestinationMACAddress(ethPkt.getSourceMACAddress());
					ethPkt.setSourceMACAddress(ethPkt.getSourceMACAddress());
					
					SwitchCommands.sendPacket(sw, (short)pktIn.getInPort(), ethPkt);
					
				}		
			}
		}
		
		return Command.CONTINUE;
	} 
	
	/**
	 * Returns the MAC address for a host, given the host's IP address.
	 * @param hostIPAddress the host's IP address
	 * @return the hosts's MAC address, null if unknown
	 */
	private byte[] getHostMACAddress(int hostIPAddress)
	{
		Iterator<? extends IDevice> iterator = this.deviceProv.queryDevices(null, null, hostIPAddress, null, null);
		if (!iterator.hasNext())
		{ return null; }
		IDevice device = iterator.next();
		return MACAddress.valueOf(device.getMACAddress()).toBytes();
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{ /* Nothing we need to do, since the switch is no longer active */ }

	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId)
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when a port on a switch goes up or down, or is
	 * added or removed.
	 * @param DPID for the switch
	 * @param port the port on the switch whose status changed
	 * @param type the type of status change (up, down, add, remove)
	 */
	@Override
	public void switchPortChanged(long switchId, ImmutablePort port,
			PortChangeType type) 
	{ /* Nothing we need to do, since load balancer rules are port-agnostic */}

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{ return null; }

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ return null; }

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> floodlightService =
	            new ArrayList<Class<? extends IFloodlightService>>();
        floodlightService.add(IFloodlightProviderService.class);
        floodlightService.add(IDeviceService.class);
        return floodlightService;
	}

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) 
	{
		return (OFType.PACKET_IN == type 
				&& (name.equals(ArpServer.MODULE_NAME) 
					|| name.equals(DeviceManagerImpl.MODULE_NAME))); 
	}

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) 
	{ return false; }
}

