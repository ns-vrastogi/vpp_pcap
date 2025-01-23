# This is the VPP packet capture script. 
## We can run the script below steps. 
1. Clont the repository using the command.
   git clone https://github.com/ns-vrastogi/vpp_pcap.git
2. Go to vpp_pcap directory and make the Python script executable.
   chmod +x packet_capture.py
3. Run the Python script with the required filters.
   python3 packet_capture.py


The script accepts the below arguments. 

optional arguments:

  -h, --help            show this help message and exit
  
  -t TIME, --time, TIME  Number of seconds for which script captures packets by default its 10 seconds
  
  -c COUNT, --count, COUNT Number of packet you want to capture, default is 1000 packets
								
  -v, --verbose, give detailed information like TLV will be shown
  
  -d DESTINATION_IP, --destination_ip DESTINATION_IP Pass the destination IP
  
  -s SOURCE_IP, --source_ip SOURCE_IP Pass the source IP
  
  -sp SOURCE_PORT, --source-port SOURCE_PORT Pass the source port
  
  -dp DESTINATION_PORT, --destination-port DESTINATION_PORT Pass the destination port
  
  -p PROTOCOL, --protocol, PROTOCOL Pass the protocol
  
  -vl VLAN, --vlan VLAN, Pass the vlan ID

</br>
