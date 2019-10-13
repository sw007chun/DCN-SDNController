package edu.nyu.cs.sdn.apps.sps;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMatchField;
import org.openflow.protocol.OFOXMFieldType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.instruction.OFInstruction;
import org.openflow.protocol.instruction.OFInstructionApplyActions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.nyu.cs.sdn.apps.util.Host;
import edu.nyu.cs.sdn.apps.util.SwitchCommands;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitch.PortChangeType;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceListener;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;

public class ShortestPathSwitching implements IFloodlightModule, IOFSwitchListener, 
		ILinkDiscoveryListener, IDeviceListener, InterfaceShortestPathSwitching
{
	public static final String MODULE_NAME = ShortestPathSwitching.class.getSimpleName();
	
	// Interface to the logging system
    private static Logger log = LoggerFactory.getLogger(MODULE_NAME);
    
    // Interface to Floodlight core for interacting with connected switches
    private IFloodlightProviderService floodlightProv;

    // Interface to link discovery service
    private ILinkDiscoveryService linkDiscProv;

    // Interface to device manager service
    private IDeviceService deviceProv;
    
    // Switch table in which rules should be installed
    public static byte table;
    
    // Map of hosts to devices
    private Map<IDevice,Host> knownHosts;

	/**
     * Loads dependencies and initializes data structures.
     */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException 
	{
		log.info(String.format("Initializing %s...", MODULE_NAME));
		Map<String,String> config = context.getConfigParams(this);
        this.table = Byte.parseByte(config.get("table"));
        
		this.floodlightProv = context.getServiceImpl(IFloodlightProviderService.class);
        this.linkDiscProv = context.getServiceImpl(ILinkDiscoveryService.class);
        this.deviceProv = context.getServiceImpl(IDeviceService.class);
        
        this.knownHosts = new ConcurrentHashMap<IDevice,Host>();
        
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
		this.linkDiscProv.addListener(this);
		this.deviceProv.addListener(this);
		
		/*********************************************************************/
		/* TODO: Perform other tasks, if necessary                           */
		/*********************************************************************/
	}
	
	/**
	 * Get the shortest path tree using Dijkstra's algorithm for each switch node
	 */
	private Map<Long, Integer> getShortestPath(Long sourceSwitchId)
	{
		//distance and predecessor for Bellman Ford algorithm
		
		Map<Long, Integer> distance = new ConcurrentHashMap<Long, Integer>(); 	//switchID and distance pair
		Map<Long, Integer> predecessor = new ConcurrentHashMap<Long, Integer>(); //switchID and predecessor port pair
		
		Map<Long, IOFSwitch> allSwitches = this.getSwitches();
		Collection<Link> allLinks = this.getLinks();
		
//		log.info(String.format("computing shortest path %s ...", sourceSwitchId));
		
		//initializing the distance of nodes
		for (Long switchID : allSwitches.keySet())
		{
			distance.put(switchID, Integer.MAX_VALUE-1);
		}
		distance.put(sourceSwitchId, 0);
		
		for (int sNum = 0 ; sNum < allSwitches.size() ; sNum++ )
		{
			for (Link link : allLinks) 
			{
				//checking the distance in both direction because this network is undirected graph
				if (distance.get(link.getSrc()) + 1 < distance.get(link.getDst()))
				{
					distance.put(link.getDst(), distance.get(link.getSrc()) + 1);
					predecessor.put(link.getDst(), link.getDstPort());
				} 
				else if (distance.get(link.getDst()) + 1 < distance.get(link.getSrc()))
				{
					distance.put(link.getSrc(), distance.get(link.getDst()) + 1);
					predecessor.put(link.getSrc(), link.getSrcPort());
				}
			}
		}
		
		return predecessor;
	}
	
	/**
	 * Add rules to the nodes
	 */
	private void addSwitchRules(Host host)
	{
		//I don't know but mininet keeps making a phantom host, so I have to check if it is not a phantom host
		if (host.getIPv4Address() == null) return;
		
		log.info(String.format("address %s rule...", host.getIPv4Address()));
		log.info(String.format("installing %s rule...", host.getName()));
		
		//get the switch which host is attached
		IOFSwitch hostSwitch = host.getSwitch();

		log.info(String.format("id %d rule...", hostSwitch.getId()));
		
		Map<Long, Integer> shortestPathTree = this.getShortestPath(hostSwitch.getId());
		
		//since we have calculated shortest paths between switches we have to add the host is predecessor of its attached switch
		shortestPathTree.put(hostSwitch.getId(), host.getPort()); 
		
		Map<Long, IOFSwitch> allSwitches = this.getSwitches();
		
		//match the destination IP address is the host we have calculated the shortest path
		OFMatchField dstEthType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
		OFMatchField dstIpAddr = new OFMatchField(OFOXMFieldType.IPV4_DST, host.getIPv4Address());
		
		ArrayList<OFMatchField> dstMatchField = new ArrayList<OFMatchField>();
		dstMatchField.add(dstEthType);
		dstMatchField.add(dstIpAddr);
		
		OFMatch dstMatch = new OFMatch();
		dstMatch.setMatchFields(dstMatchField);
		
		for (Long switchID : allSwitches.keySet())
		{
			if (shortestPathTree.get(switchID) != null )
			{
//				log.info(String.format("adding switchID %s rule...", switchID));
				OFAction action = new OFActionOutput(shortestPathTree.get(switchID));
				OFInstruction instructions = new OFInstructionApplyActions(Arrays.asList(action));
				SwitchCommands.installRule(allSwitches.get(switchID), this.table, SwitchCommands.DEFAULT_PRIORITY, dstMatch, Arrays.asList(instructions));
			}
		}
	}
	
	/**
	 * Remove rules from the nodes
	 */
	private void removeRules(Host host)
	{		
		//I don't know but mininet keeps making a phantom host, so I have to check if it is not a phantom host
		if (host.getIPv4Address() == null) return;
		
		log.info(String.format("removing %s rule...", host.getName()));
		
		//removing by matching the same installed criteria
		OFMatchField dstEthType = new OFMatchField(OFOXMFieldType.ETH_TYPE, Ethernet.TYPE_IPv4);
		OFMatchField dstIpAddr = new OFMatchField(OFOXMFieldType.IPV4_DST, host.getIPv4Address());
		
		ArrayList<OFMatchField> dstMatchField = new ArrayList<OFMatchField>();
		dstMatchField.add(dstEthType);
		dstMatchField.add(dstIpAddr);
		
		OFMatch dstMatch = new OFMatch();
		dstMatch.setMatchFields(dstMatchField);
		
		for (IOFSwitch swch : this.getSwitches().values())
		{
			SwitchCommands.removeRules(swch, this.table, dstMatch);
		}
	}
	
	/**
	 * Get the table in which this application installs rules.
	 */
	public byte getTable()
	{ return this.table; }
	
    /**
     * Get a list of all known hosts in the network.
     */
    private Collection<Host> getHosts()
    { return this.knownHosts.values(); }
	
    /**
     * Get a map of all active switches in the network. Switch DPID is used as
     * the key.
     */
	private Map<Long, IOFSwitch> getSwitches()
    { return floodlightProv.getAllSwitchMap(); }
	
    /**
     * Get a list of all active links in the network.
     */
    private Collection<Link> getLinks()
    { return linkDiscProv.getLinks().keySet(); }

    /**
     * Event handler called when a host joins the network.
     * @param device information about the host
     */
	@Override
	public void deviceAdded(IDevice device) 
	{
		Host host = new Host(device, this.floodlightProv);
		// We only care about a new host if we know its IP
		if (host.getIPv4Address() != null)
		{
			log.info(String.format("Host %s added", host.getName()));
			this.knownHosts.put(device, host);
			
			/*****************************************************************/
			/* TODO: Update routing: add rules to route to new host          */
			/*****************************************************************/
			
			//we just add rules when new host is attached
			//because other hosts routes is not effected by newly added host
			this.addSwitchRules(host);
		}
	}

	/**
     * Event handler called when a host is no longer attached to a switch.
     * @param device information about the host
     */
	@Override
	public void deviceRemoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		log.info(String.format("Host %s is no longer attached to a switch", 
				host.getName()));
		
		/*********************************************************************/
		/* TODO: Update routing: remove rules to route to host               */
		/*********************************************************************/
		//we just remove rules when new host is attached
		//because other hosts routes is not effected by removed host
		this.removeRules(host);
	}
	/**
     * Event handler called when a host moves within the network.
     * @param device information about the host
     */
	@Override
	public void deviceMoved(IDevice device) 
	{
		Host host = this.knownHosts.get(device);
		if (null == host)
		{
			host = new Host(device, this.floodlightProv);
			this.knownHosts.put(device, host);
		}
		
		if (!host.isAttachedToSwitch())
		{
			this.deviceRemoved(device);
			return;
		}
		log.info(String.format("Host %s moved to s%d:%d", host.getName(),
				host.getSwitch().getId(), host.getPort()));
		
		/*********************************************************************/
		/* TODO: Update routing: change rules to route to host               */
		/*********************************************************************/
		
		//we remove the original rules and recalculate the paths from the host
		this.removeRules(host);
		this.addSwitchRules(host);
	}
	
    /**
     * Event handler called when a switch joins the network.
     * @param DPID for the switch
     */
	@Override		
	public void switchAdded(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d added", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/
		
		//one switch can change the pathes so we recalculate paths of all hosts
		for (Host host : getHosts())
		{
			log.info(String.format("host h%n added", host.getName()));
			this.removeRules(host);
			this.addSwitchRules(host);
		}
	}

	/**
	 * Event handler called when a switch leaves the network.
	 * @param DPID for the switch
	 */
	@Override
	public void switchRemoved(long switchId) 
	{
		IOFSwitch sw = this.floodlightProv.getSwitch(switchId);
		log.info(String.format("Switch s%d removed", switchId));
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/
		
		//one switch can change the pathes so we recalculate paths of all hosts
		for (Host host : getHosts())
		{
			this.removeRules(host);
			this.addSwitchRules(host);
		}
	}

	/**
	 * Event handler called when multiple links go up or down.
	 * @param updateList information about the change in each link's state
	 */
	@Override
	public void linkDiscoveryUpdate(List<LDUpdate> updateList) 
	{
		for (LDUpdate update : updateList)
		{
			// If we only know the switch & port for one end of the link, then
			// the link must be from a switch to a host
			if (0 == update.getDst())
			{
				log.info(String.format("Link s%s:%d -> host updated", 
					update.getSrc(), update.getSrcPort()));
			}
			// Otherwise, the link is between two switches
			else
			{
				log.info(String.format("Link s%s:%d -> %s:%d updated", 
					update.getSrc(), update.getSrcPort(),
					update.getDst(), update.getDstPort()));
			}
		}
		
		/*********************************************************************/
		/* TODO: Update routing: change routing rules for all hosts          */
		/*********************************************************************/
		
		//one link can change the pathes so we recalculate paths of all hosts
		for (Host host : getHosts())
		{
			this.removeRules(host);
			this.addSwitchRules(host);
		}
	}

	/**
	 * Event handler called when link goes up or down.
	 * @param update information about the change in link state
	 */
	@Override
	public void linkDiscoveryUpdate(LDUpdate update) 
	{ this.linkDiscoveryUpdate(Arrays.asList(update)); }
	
	/**
     * Event handler called when the IP address of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceIPV4AddrChanged(IDevice device) 
	{ this.deviceAdded(device); }

	/**
     * Event handler called when the VLAN of a host changes.
     * @param device information about the host
     */
	@Override
	public void deviceVlanChanged(IDevice device) 
	{ /* Nothing we need to do, since we're not using VLANs */ }
	
	/**
	 * Event handler called when the controller becomes the master for a switch.
	 * @param DPID for the switch
	 */
	@Override
	public void switchActivated(long switchId) 
	{ /* Nothing we need to do, since we're not switching controller roles */ }

	/**
	 * Event handler called when some attribute of a switch changes.
	 * @param DPID for the switch
	 */
	@Override
	public void switchChanged(long switchId) 
	{ /* Nothing we need to do */ }
	
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
	{ /* Nothing we need to do, since we'll get a linkDiscoveryUpdate event */ }

	/**
	 * Gets a name for this module.
	 * @return name for this module
	 */
	@Override
	public String getName() 
	{ return this.MODULE_NAME; }

	/**
	 * Check if events must be passed to another module before this module is
	 * notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPrereq(String type, String name) 
	{ return false; }

	/**
	 * Check if events must be passed to another module after this module has
	 * been notified of the event.
	 */
	@Override
	public boolean isCallbackOrderingPostreq(String type, String name) 
	{ return false; }
	
    /**
     * Tell the module system which services we provide.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() 
	{
		Collection<Class<? extends IFloodlightService>> services =
					new ArrayList<Class<? extends IFloodlightService>>();
		services.add(InterfaceShortestPathSwitching.class);
		return services; 
	}

	/**
     * Tell the module system which services we implement.
     */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> 
			getServiceImpls() 
	{ 
        Map<Class<? extends IFloodlightService>, IFloodlightService> services =
        			new HashMap<Class<? extends IFloodlightService>, 
        					IFloodlightService>();
        // We are the class that implements the service
        services.put(InterfaceShortestPathSwitching.class, this);
        return services;
	}

	/**
     * Tell the module system which modules we depend on.
     */
	@Override
	public Collection<Class<? extends IFloodlightService>> 
			getModuleDependencies() 
	{
		Collection<Class<? extends IFloodlightService >> modules =
	            new ArrayList<Class<? extends IFloodlightService>>();
		modules.add(IFloodlightProviderService.class);
		modules.add(ILinkDiscoveryService.class);
		modules.add(IDeviceService.class);
        return modules;
	}
}
