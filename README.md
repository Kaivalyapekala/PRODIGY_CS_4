# PRODIGY_CS_5
import socket
import struct
import textwrap

def unpack_ethernet_frame(data):
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', data[:14])
    return format_mac_address(dest_mac), format_mac_address(src_mac), socket.htons(eth_proto), data[14:]

def format_mac_address(mac):
    return ':'.join(map('{:02x}'.format, mac))

def unpack_ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4_address(src), format_ipv4_address(dest), data[header_length:]

def format_ipv4_address(addr):
    return '.'.join(map(str, addr))

def unpack_tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def format_packet_data(data):
    return '\n'.join(textwrap.wrap(data, 80))

def packet_sniffer():
    # Create a raw socket and bind it to the network interface
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    try:
        while True:
            raw_data, addr = sock.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = unpack_ethernet_frame(raw_data)
            
            # IPv4
            if eth_proto == 8:
                version, header_length, ttl, proto, src, dest, data = unpack_ipv4_packet(data)
                
                # TCP
                if proto == 6:
                    src_port, dest_port, sequence, acknowledgment, urg, ack, psh, rst, syn, fin, data = unpack_tcp_segment(data)
                    print(f'\n\nEthernet Frame:')
                    print(f'Destination MAC: {dest_mac}, Source MAC: {src_mac}, Ethernet Protocol: {eth_proto}')
                    print(f'IPv4 Packet:')
                    print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}, Protocol: {proto}')
                    print(f'Source IP: {src}, Destination IP: {dest}')
                    print(f'TCP Segment:')
                    print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                    print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                    print(f'Flags: URG: {urg}, ACK: {ack}, PSH: {psh}, RST: {rst}, SYN: {syn}, FIN: {fin}')
                    print('Data:')
                    print(format_packet_data(data))

    except KeyboardInterrupt:
        print("\nSniffer terminated.")

if __name__ == "__main__":
    packet_sniffer()
