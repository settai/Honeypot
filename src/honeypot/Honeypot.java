package honeypot;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
//import java.util.List;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
//import org.jnetpcap.util.checksum.Checksum;

public class Honeypot {
    private static final String WINDOWS_CMD = "ipconfig";
    private static final String LINUX_CMD = "ifconfig";
    private static final String DEFAULT_GATEWAY = "Default Gateway";

    private ArpTable arpTable;
    private String gatewayIpAddress, gatewayMacAddress;
    
    Honeypot(){
        // Save Interface and gateway addresses
        try{
            // Gateway ip address
            Process result = Runtime.getRuntime().exec("netstat -rn");

            BufferedReader output = new BufferedReader(new InputStreamReader(result.getInputStream()));

            String line = output.readLine();
            while(line != null){
                if ( line.trim().startsWith("default") == true || line.trim().startsWith("0.0.0.0") == true )
                    break;      
                line = output.readLine();
            }
            if(line==null) //gateway not found;
                return;

            StringTokenizer st = new StringTokenizer( line );
            st.nextToken();
            gatewayIpAddress = st.nextToken();
            
            // Gateway mac address
            
            result = Runtime.getRuntime().exec("ip neigh");

            output = new BufferedReader(new InputStreamReader(result.getInputStream()));

            line = output.readLine();
            while(line != null){
                if ( line.trim().startsWith(gatewayIpAddress) == true)
                    break;      
                line = output.readLine();
            }
            if(line==null) //gateway not found;
                return;

            st = new StringTokenizer( line );
            st.nextToken(); st.nextToken();
            st.nextToken(); st.nextToken();
            gatewayMacAddress = st.nextToken();
            
            //System.out.println(gatewayIpAddress + " " + gatewayMacAddress);

        } catch( Exception e ) { 
            System.out.println( e.toString() );
        }
        
    }
    
    public void start(){
        try {
            // Will be filled with NICs (network interface card)
            ArrayList<PcapIf> alldevs = new ArrayList<PcapIf>();

            // For any error msgs
            StringBuilder errbuf = new StringBuilder();

            //Getting a list of devices
            int r = Pcap.findAllDevs(alldevs, errbuf);
            System.out.println(r);
            
            if (r != Pcap.OK) {
                System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
                return;
            }

            System.out.println("Network devices found:");
            int i = 0;
            for (PcapIf device : alldevs) {
                String description
                        = (device.getDescription() != null) ? device.getDescription()
                        : "No description available";
                System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
            }
            System.out.println("choose the one device from above list of devices");
            int ch = new Scanner(System.in).nextInt();
            PcapIf device = alldevs.get(ch);
            
            System.out.println("choosing " + device);
            
            int snaplen = 64 * 1024;           // Capture all packets, no trucation
            int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
            int timeout = 10 * 1000;           // 10 seconds in millis

            //Open the selected device to capture packets
            Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

            if (pcap == null) {
                System.err.printf("Error while opening device for capture: "
                        + errbuf.toString());
                return;
            }
            System.out.println("device opened");

            //Create packet handler which will receive packets
            PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
                Arp arp = new Arp();
                Tcp tcp = new Tcp();
                Udp udp = new Udp();
                Ip4 ip4 = new Ip4();
                
                public void nextPacket(PcapPacket packet, String user) {   
                    if(packet.hasHeader(ip4))
                        testWhitelist(packet);
                    
                    if (packet.hasHeader(arp) && arp.operationEnum() == Arp.OpCode.REPLY) {
                        testSpoofing(arp);
                    }
                                        
                    if (packet.hasHeader(tcp) && packet.hasHeader(ip4)) {
                        testPortScan(tcp);
                    }

                    // Capturing packet to the output
                    //printPacketInfo(packet);
                }
                
                
                public void printPacketInfo(PcapPacket packet){
                    if (packet.hasHeader(arp)) {
                        System.out.println("--> arp packet detected");
                        System.out.println("Hardware type" + arp.hardwareType());
                        System.out.println("Protocol type" + arp.protocolType());
                        System.out.println("Packet:" + arp.getPacket());
                        System.out.println();                        
                    }

                    if (packet.hasHeader(Tcp.ID) && packet.hasHeader(ip4)) {
                        System.out.println("--> tcp packet detected");
                        final Tcp tcp = packet.getHeader(new Tcp());
                        System.out.println("Tcp Source Port :" + tcp.source());
                        System.out.println("Tcp Destination Port :" + tcp.destination());

                        System.out.println("Ip4 Source :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.source())));
                        System.out.println("Ip4 Destination  :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.destination())));

                        // System.out.println(Arrays.toString(byteArray));
                        // org.jnetpcap.packet.format.FormatUtils.ip(sIP)
                    }

                    if (packet.hasHeader(Udp.ID) && packet.hasHeader(ip4)) {
                        System.out.println("--> udp packet detected");
                        final Udp udp = packet.getHeader(new Udp());
                        System.out.println("Udp Source Port :" + udp.source());
                        System.out.println("Udp Destination Port :" + udp.destination());

                        System.out.println("Ip4 Source :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.source())));
                        System.out.println("Ip4 Destination  :" + org.jnetpcap.packet.format.FormatUtils.ip((ip4.destination())));

                        // System.out.println(Arrays.toString(byteArray));
                        // org.jnetpcap.packet.format.FormatUtils.ip(sIP)
                    }
                }

            };
            //we enter the loop and capture the 20 packets here.You can  capture any number of packets just by changing the first argument to pcap.loop() function below
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jnetpcap rocks!");
            
            //Close the pcap
            pcap.close();
        } catch (Exception ex) {
            System.out.println(ex);
        }
    } 
    
    public void testSpoofing(Arp arp){
        try {
            if(getArpSenderIP(arp).equals(gatewayIpAddress) && ! getArpSenderMAC(arp).equals(gatewayMacAddress)){
                System.out.println("spoofing attempt detected");
            }
        } catch (IOException ex) {
            Logger.getLogger(Honeypot.class.getName()).log(Level.SEVERE, null, ex);
        }
    }


    public void testPortScan(Tcp tcp){
        //we should be receiving only syn S packet
        if(tcp.flags_SYN() && gatewayIpAddress.equals(tcp.source())){
            System.out.println("port scan attempt detected");
        }
    }

    public void testWhitelist(PcapPacket packet){
        Arp arp = new Arp();
        Udp udp = new Udp();
        if (packet.hasHeader(udp)) {
            //we shouldnt be getting udp packet except from dns server
            if(!isDns(packet)){
                System.out.println("suspicious udp packet detected");
                //System.out.println(packet.toString());
            }
        }

        //we shouldnt get any arp request
        if (packet.hasHeader(arp) && arp.operationEnum() != Arp.OpCode.REPLY) {
            try {
                if(!getArpSenderIP(arp).equals(gatewayIpAddress)){
                    System.out.println("suspicious arp packet detected");
                }
            } catch (IOException ex) {
                Logger.getLogger(Honeypot.class.getName()).log(Level.SEVERE, null, ex);
            }
        }

    }

    private boolean isDns(final PcapPacket packet) {
        if (packet.hasHeader(Udp.ID)) {
            final Udp udp = packet.getHeader(new Udp());
            return (udp.source() == 53 || udp.destination() == 53);
        }
        else if (packet.hasHeader(Tcp.ID)) {
            final Tcp tcp = packet.getHeader(new Tcp());
            return (tcp.source() == 53 || tcp.destination() == 53);
        }
        return false;
    }

    public String getArpSenderIP(Arp arp) throws IOException{
        BufferedReader output = new BufferedReader(new StringReader(arp.getPacket().toString()));

        String line = output.readLine();
        while(line != null){
            if ( line.contains("sender IP") == true )
                break;      
            line = output.readLine();
        }
        if(line==null) //gateway not found;
            return "";

        StringTokenizer st = new StringTokenizer( line, "=" );
        st.nextToken();
        return st.nextToken().trim();
    }

    public String getArpSenderMAC(Arp arp) throws IOException {
        BufferedReader output = new BufferedReader(new StringReader(arp.getPacket().toString()));

        String line = output.readLine();
        while(line != null){
            if ( line.contains("sender MAC") == true )
                break;      
            line = output.readLine();
        }
        if(line==null) //gateway not found;
            return "";

        StringTokenizer st = new StringTokenizer( line, "=" );
        st.nextToken();
        return st.nextToken().trim();
    }
    
    
    public static void main(String[] args) throws Exception {
        Honeypot honeypot = new Honeypot();
        honeypot.start();
    }
}

