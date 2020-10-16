/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package honeypot;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Scanner;
import java.util.Set;
import java.util.StringTokenizer;


public class ArpTable  {
    public static final String ARP_GET_IP_HW = "arp -a";
    Hashtable<String, String> addresses;

    public ArpTable(String cmd) throws IOException {
        addresses = new Hashtable<String, String>();
        Scanner s = new Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
        StringTokenizer st;
        String line;
        
        
        while(s.hasNext()){
            line = s.nextLine();
            //System.out.println(line);
            if(line.matches("(.*)dynamic(.*)")){
                st = new StringTokenizer(line);
                String ip = st.nextToken(), mac = st.nextToken();
                addresses.put(ip, mac);
            }
        }
    }
    
    public Hashtable<String, String> getArpTable(){
        return addresses;
    }
    
    public void test(){
        Set<String> keySet = new HashSet<>(addresses.keySet());
        for(String ip1 : addresses.keySet()){ 
            keySet.remove(ip1);
            for(String ip2 : keySet){
                String mac1 = addresses.get(ip1), mac2 = addresses.get(ip2);
                if(!ip1.equals(ip2)  && mac1.equals(mac2)){
                    System.out.println("Warnning : the " + ip1 + " and " + ip2 
                            + "sharing the same MAC addresse" + mac1); 
                }
            }
        }
    }
    
    public static void main(String[] args) throws IOException {
       ArpTable arptable = new ArpTable(ARP_GET_IP_HW);
       arptable.test();
    }  
    
}