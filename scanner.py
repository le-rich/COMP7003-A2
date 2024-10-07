from scapy.all import sniff

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")
    return ether_type

def parse_arp_packet(hex_data):
    hardware_type = hex_data[28:32]
    protocol_type = hex_data[32:26]
    hardware_size = hex_data[36:38]
    protocol_size = hex_data[38:40]
    opcode = hex_data[40:44]
    sender_mac = hex_data[44:56]
    sender_ip = hex_data[56:64]
    target_mac = hex_data[64:76]
    target_ip = hex_data[76:84]

    print("ARP Packet =======")
    print(f"Hardware Type: HEX: {hardware_type} ,INT: {int(hardware_type, 16)}")
    print(f"Protocol Type: HEX: {protocol_type}, INT: {int(protocol_type, 16)}")
    print(f"Hardware Length: HEX: {hardware_size}, INT: {int(hardware_size, 16)}")
    print(f"Protocol Length: HEX: {protocol_size}, INT: {int(protocol_size, 16)}")
    print(f"Opcode: HEX: {opcode}, INT: {int(opcode, 16)}")
    print(f"Sender MAC Address: {":".join(sender_mac[i:i+2] for i in range(0, 12, 2))}")
    print(f"Sender IP Address: {":".join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    print(f"Target MAC Address: {":".join(target_mac[i:i+2] for i in range(0, 12, 2))}")
    print(f"Target IP Address: {":".join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    return protocol

def parse_ipv4_packet(hex_data):
    version = hex_data[28:29]
    ihl = hex_data[29:30]
    type_of_service = hex_data[30:32]
    total_length = hex_data[32:36]
    identification = hex_data[36:40]

    flags_fragment_offset = hex_data[40:44]
    flag_bits = bin(int(flags_fragment_offset[:1], 16))[2:].zfill(4)[-3:]
    fragment_offset_bits = int(flags_fragment_offset[1:], 16) # CONVERTED TO INT HERE

    ttl = hex_data[44:46]
    protocol = hex_data[46:48]
    header_checksum = hex_data[48:52]
    source_ip = hex_data[52:60]
    destination_ip = hex_data[60:68]

    print("IPV4 Packet =======")
    print(f"Version: HEX: {version}, INT: {int(version, 16)}")
    print(f"IHL: HEX: {ihl}, INT: {int(ihl, 16)}")
    print(f"Type of Service: HEX: {type_of_service}, INT: {int(type_of_service, 16)}")
    print(f"Total Length: HEX: {total_length}, INT: {int(total_length, 16)}")
    print(f"Identification: HEX: {identification}, INT: {int(identification, 16)}")

    # Special Print for Flags and Fragment Offset
    print(f"Flags: BINARY: {flags_bits}")
    print(f"    Reserved bit: {flags_bits[0]}")
    print(f"    Don't Fragment (DF): {flags_bits[1]}")
    print(f"    More Fragments (MF): {flags_bits[2]}")
    print(f"Fragment Offset: HEX: {flags_fragment_offset[1:]}, INT: {fragment_offset_bits}")

    print(f"Time to Live (TTL): HEX: {ttl}, INT: {int(ttl, 16)}")
    print(f"Protocol: HEX: {protocol}, INT: {int(protocol, 16)}")
    print(f"Header Checksum: HEX: {header_checksum}, INT: {int(header_checksum, 16)}")
    print(f"Source IP Address: {'.'.join(str(int(source_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    print(f"Destination IP Address: {'.'.join(str(int(dest_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    ip_header_length = ihl * 4 * 2
    return protocol, 28 + ip_header_length

def parse_tcp_packet(hex_data, tcp_start):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    sequence_number = hex_data[76:84]
    acknowledgement_number = hex_data[84:92]
    data_offset_reserved_flags = hex_data[92:96]

    data_offset = int(data_offset_reserved_flags[0], 16)
    reserved_bits = bin(int(data_offset_reserved_flags[1], 16))[2:].zfill(4)[:3]
    flags_bits = bin(int(data_offset_reserved_flags[1:], 16))[2:].zfill(9)[-9:]
   
    window_size = hex_data[96:100]
    checksum = hex_data[100:104]
    urgent_pointer = hex_data[104:108]

    print("=== TCP Packet ===")
    print(f"Source Port: HEX: {source_port}, INT: {int(source_port, 16)}")
    print(f"Destination Port: HEX: {destination_port}, INT: {int(destination_port, 16)}")
    print(f"Sequence Number: HEX: {sequence_number}, INT: {int(sequence_number, 16)}")
    print(f"Acknowledgment Number: HEX: {acknowledgment_number}, INT: {int(acknowledgment_number, 16)}")
    print(f"Data Offset: HEX: {hex(data_offset)}, INT: {data_offset}")
    print(f"Reserved Bits: BINARY: {reserved_bits}")
   
    print(f"Flags: BINARY: {flags_bits}")
    print(f"    CWR: {flags_bits[0]}")
    print(f"    ECE: {flags_bits[1]}")
    print(f"    URG: {flags_bits[2]}")
    print(f"    ACK: {flags_bits[3]}")
    print(f"    PSH: {flags_bits[4]}")
    print(f"    RST: {flags_bits[5]}")
    print(f"    SYN: {flags_bits[6]}")
    print(f"    FIN: {flags_bits[7]}")

    print(f"Window Size: HEX: {window_size}, INT: {int(window_size, 16)}")
    print(f"Checksum: HEX: {checksum}, INT: {int(checksum, 16)}")
    print(f"Urgent Pointer: HEX: {urgent_pointer}, INT: {int(urgent_pointer, 16)}")
    
    tcp_header_length = data_offset * 4 * 2
    payload_data = hex_data[tcp_start + tcp_header_length:]
    print(f"Payload HEX: {payload_data}")

def parse_udp_packet(hex_data, udp_start):
    source_port = hex_data[68:72]
    destination_port = hex_data[72:76]
    rength = hex_data[76:80]
    checksum = hex_data[80:84]
   
    print("=== UDP Packet ===")
    print(f"Source Port: HEX: {src_port}, INT: {int(source_port, 16)}")
    print(f"Destination Port: HEX: {dest_port}, INT: {int(destination_port, 16)}")
    print(f"Length: HEX: {length}, INT: {int(length, 16)}")
    print(f"Checksum: HEX: {checksum}, INT: {int(checksum, 16)}")

    payload_data = hex_data[udp_start + 16:]
    print(f"Payload HEX: {payload_data}")

# Function to handle each captured packet
def packet_callback(packet):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    ether_type = parse_ethernet_header(hex_data)

    # PROTOCOL NUMS HERE IN HEX
    # ARP
    if ether_type == "0806":
        parse_arp_packet(hex_data)
    elif ether_type == "0800":
        protocol, ip_payload_start  = parse_ipv4_packet(hex_data)
        # TCP
        if (protocol == "06"):
            parse_tcp_packet(hex_data, ip_payload_start)
        elif (protocol == "11"):
            prase_udp_packet(hex_data, ip_payload_start)


def show_interactive_filter():
    print ("Select a filter type:")
    print ("1 -- ARP")
    print ("2 -- TCP")
    print ("3 -- UDP")
    print ("4 -- Custom Port")

    userChoice = input("")
    if choice == '1':
        return "arp"
    elif choice == '2':
        return "tcp"
    elif choice == '3':
        return "udp"
    elif choice == '4':
        portNum = input("Enter the port number to listen to: ")
        return f"port {portNum}"
    else
        return "ERR: INVALID FILTER"

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    print(f"Starting packet capture on {interface} with filter: {capture_filter}")
    sniff(iface=interface, filter=capture_filter, prn=packet_callback, count=packet_count)

def main ():
    interface = input("Enter your network interface: ")
    capture_filter = show_interactive_filter()
    if capture_filter == "ERR: INVALID FILTER":
        return -1
    packet_count = int(input("Enter the number of packets to capture: "))
    capture_packets(interface,capture_filter, packet_count)

if __name__ == "__main__":
    main()
