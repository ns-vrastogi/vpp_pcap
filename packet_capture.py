import argparse
import subprocess
import time
from scapy.layers.inet import IP, UDP, GRE, Ether, TCP, ICMP
from scapy.all import rdpcap, Raw, wrpcap
from datetime import datetime


def pcap_name():
    now = datetime.now()
    name = now.strftime("capture"+"%d_%m_%H_%M" + '.pcap')
    return name

def ip_to_hex(ip_address):
  octets = ip_address.split('.')
  hex_octets = [hex(int(octet))[2:].zfill(2) for octet in octets]
  hex_ip = ''.join(hex_octets)
  print(hex_ip)
  return hex_ip

def port_to_hex(port):
    try:
        port = int(port)
        if 0 <= port <= 65535:
            return f"{port:04x}"  # Convert to hex and ensure it's 4 characters
        else:
            raise ValueError("Port number must be between 0 and 65535.")
    except ValueError:
        raise ValueError(f"Invalid port number: {port}")


def protocol_to_hex(proto):
    print(proto)
    if proto == "tcp":
        return '06'
    if proto == "udp":
        return '11'
    if proto == 'icmp':
        return '01'

def configure_capture(seconds, count, Verbose=False ,src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol=None, vlan=None):
    mask = '0' * 96
    mask_filter = '0' * 96


    if src_ip:
        print("capturing pcap for source IP")
        hex_ip = ip_to_hex(src_ip)
        mask = mask[:60] + 'f' * 8 + mask[68:]
        mask_filter = mask_filter[:60] + hex_ip + mask_filter[60:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'

    if dst_ip:
        print("capturing pcap for destination ip")
        hex_ip = ip_to_hex(dst_ip)
        mask = mask[:68] + 'f' * 8 + mask[76:]
        mask_filter = mask_filter[:68] + hex_ip + mask_filter[76:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'

    if src_port:
        print("capturing pcap for source port")
        hex_port = port_to_hex(src_port)
        mask = mask[:76] + 'f'*4 + mask[80:]
        mask_filter = mask_filter[:76] + hex_port + mask_filter[80:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'

    if dst_port:
        print("capturing pcap for source port")
        hex_port = port_to_hex(dst_port)
        mask = mask[:80]+ 'f' * 4 + mask[84:]
        mask_filter = mask_filter[:80] + hex_port + mask_filter[84:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'

    if protocol:
        print('############')
        hex_proto = protocol_to_hex(protocol)
        print(hex_proto)
        mask = mask[:54] + 'f'*2 + mask[56:]
        mask_filter = mask_filter[:54] + hex_proto + mask_filter[56:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'

    if vlan:
        hex_vlan = port_to_hex(vlan)
        mask = mask[:28] + 'f' * 4 + mask[32:]
        mask_filter = mask_filter[:28] + hex_vlan + mask_filter[32:]
        command = f'sudo vppctl classify filter pcap mask hex {mask} match hex {mask_filter}'


    name = pcap_name()
    print(command)
    subprocess.run(command, shell=True)
    time.sleep(1)
    command2 = f'sudo vppctl pcap trace max {count} file {name} rx tx filter'
    subprocess.run(command2, shell=True)
    time.sleep(seconds)
    command3 = f'sudo vppctl pcap trace max {count} file {name} rx tx filer off'
    out = subprocess.run(command3, shell=True)
    print(out)
    time.sleep(1)
    del_filter = 'sudo vppctl classify filter pcap delete'
    subprocess.run(del_filter, shell=True)
    time.sleep(2)
    subprocess.run(['chmod', '+x', 'packet_capture.py'], check=True)
    subprocess.run(['chmod', '+x', 'src/tcpdump.exe'], check=True)
    if Verbose:
        dump_command = f'./src/tcpdump.exe -n -r /tmp/{name} -vvv'
        out= subprocess.run(dump_command, shell=True)
        print(out)
    else:
        dump_command = f'./src/tcpdump.exe -n -r /tmp/{name}'
        out = subprocess.run(dump_command, shell=True)
        print(out)


def main():
    parser = argparse.ArgumentParser(description='Pass the source or destination IP')
    parser.add_argument('-t', '--time', type=int, default=10, help='Number of seconds for which script captures packets by default its 10 seconds')
    parser.add_argument('-c','--count', type=int, default=1000, help="Number of packet you want to capture, default is 1000 packets")
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-d', '--destination_ip', default=None,help='Pass the destination IP')
    parser.add_argument('-s', '--source_ip', default=None,help="Pass the source IP")
    parser.add_argument('-sp', '--source-port', default=None,help="Pass the source port")
    parser.add_argument('-dp', '--destination-port', default=None,help="Pass the destination port")
    parser.add_argument('-p', '--protocol', default=None ,help="Pass the protocol")
    parser.add_argument('-vl', '--vlan',default=None, help="Pass the vlan ID")
    args = (parser.parse_args())
    configure_capture(args.time, args.count, args.verbose, args.source_ip, args.destination_ip, args.source_port, args.destination_port, args.protocol, args.vlan)


main()


