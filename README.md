# This is the VPP packet capture script. 
## We can follow the below steps to run the script
1. Clont the git repository in VPP IPSEC/GRE node using the command.
   
   git clone https://github.com/ns-vrastogi/vpp_pcap.git
2. Go to vpp_pcap directory and make the Python script executable.
   
   chmod +x packet_capture.py
   
3. Run the Python script with the required filters.
   
   python3 packet_capture.py


The script accepts the below arguments. 

optional arguments:

  -h, --help            show this help message and exit
  
  -t TIME, --time, Number of seconds for which script captures packets by default its 10 seconds
  
  -c COUNT, --count, Number of packet you want to capture, default is 1000 packets
								
  -v, --verbose, give detailed information like TLV will be shown
  
  -d , --destination_ip,  Pass the destination IP
  
  -s, --source_ip, Pass the source IP
  
  -sp, --source-port, Pass the source port
  
  -dp, --destination-port, Pass the destination port
  
  -p , --protocol, Pass the protocol
  
  -vl, --vlan, Pass the vlan ID

</br>
