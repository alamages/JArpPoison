#JArpPoison

JArpPoison is an open source project which does arp poisoning and based on that performs two types of attacks:
	1) Network jamming(denial of service in a local network's hosts)
	2) Man in the middle attack between the router and a host(user chooses the victim)

The network jamming is done by the JNetJammer class and the MITM(Man in the middle) is done by the JMITM class.
REMEMBER in order to run these classes you need to be root

(Download the files from the src/ and compile them)

JNetJammer: 

sudo java JNetJammer --help

Usage of the Java Network Jammer
	Arguments:
	-h, --help
		Print the helptext of the jammer
	-i, --interface INTERFACE
		The network interface which will be used to perform the wifi jam
		If none(or invalid) interface is provided then a menu with the available 
		network interfaces is printed and the user can choose from there
	-b, --blacklist BLACKLISTED(comma separated) optional argument
		Comma separated ips which you do not want to hit with the jammer
	-t, --targets TARGETS(comma separated) optional argument
		By default the jammer will scan the whole ip range of the network, 
		with -t argument you can specify which ips(comma separated)
		you want to discover and then hit.

	Once you execute the jammer choose which network interface you want to use from the 
	printed menu(or provide it as a command line argument) and let the jammer to do the rest.
	Examples of usage:
		sudo java JNetJammer --targets 192.168.1.1,192.168.1.10,192.168.1.34
		sudo java JNetJammer --blacklist 192.168.1.56,192.168.1.73 -i wlan0
		sudo java JNetJammer



JMITM:

sudo java JMITM --help

Usage of JMITM
	Arguments:
	-h, --help
		Print the helptext of the JMITM
	-i, --interface INTERFACE
		The network interface which will be used to perform the MITM attack
		If none(or invalid) interface is provided then a menu with the available 
		network interfaces is printed and the user can choose from there
	-t, --targets TARGETS(comma separated) optional argument
		By default the MITM will scan the whole ip range of the network, 
		with -t argument you can specify which ips(comma separated)
		you want to discover and then choose a victim.
	-o, --output OUTPUT(optional)
		By default the JMITM will dump all the captured packets in a file steal.log
		in the current directory. With -o/--output you can override the default one 
		and can choose in which file you want the middle.java to dump/save the stolen packets.

	Once you execute the JMITM choose which network interface you want to use from the 
	printed menu(or provide it as a command line argument) and let the middle to do the rest. 
	After the host discovery choose a victim to perform the man in the middle attack.
	Examples of usage:
		sudo java JMITM -t 192.168.1.1,192.168.1.10,192.168.1.34
		sudo java JMITM --targets 192.168.1.56,192.168.1.73 -i wlan0
		sudo java JMITM --output /home/dummy.log

#JMITM and Wireshark
You can perform live packet analysis on the captured packets from the MITM attack(by default the captured are saved in a local file for offline analysis)
using wireshark

first make a fifo file:

	mkfifo /tmp/myfifo

then start your JMITM and tell it to redirect its output to the fifo file:

		sudo java JMITM --output /tmp/myfifo

finally start wireshark and tell to read from the fifo file:

	wireshark -k -i /tmp/mypipe



#Dependencies

In order to properly compile and run the JArpPoison you need to install jpcap:
More information about jpcap: http://www.eden.rutgers.edu/~muscarim/jpcap/index.html

##Screenshots

coming soon

#TODO

coming soon

##License

    JArpPoison is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

