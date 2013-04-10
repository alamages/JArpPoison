import java.io.IOException;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

public class sender {
	private NetworkInterface device = null;

	private JpcapSender sender;
	
	private void __build_sender(NetworkInterface phys_device) throws IOException {
		JpcapCaptor captor = JpcapCaptor.openDevice(phys_device,2000,false,3000); //TODO: check the params
		
		this.sender = captor.getJpcapSenderInstance();
	}
	
	public sender(NetworkInterface device) throws NullPointerException, IOException {
		this.device = device;
		if (this.device == null) throw new NullPointerException("No device has been given! sender");
		
		this.__build_sender(this.device);
	}
	
	public NetworkInterface getDevice() {
		return device;
	}

	public void setDevice(NetworkInterface device) throws IOException, NullPointerException {
		this.device = device;
		
		if (this.device == null) throw new NullPointerException("No device has been given! sender");
		this.__build_sender(device);
	}

	public JpcapSender getSender() {
		return sender;
	}

	public void setSender(JpcapSender sender) {
		this.sender = sender;
	}
	
	public void send(Packet pack){
		this.sender.sendPacket(pack);
	}
}
