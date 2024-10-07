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
    print(f"Hardware Length: HEX: {hardware_len}, INT: {int(hardware_len, 16)}")
    print(f"Protocol Length: HEX: {protocol_len}, INT: {int(protocol_len, 16)}")
    print(f"Opcode: HEX: {opcode}, INT: {int(opcode, 16)}")
    print(f"Sender MAC Address: {":".join(sender_mac[i:i+2] for i in range(0, 12, 2))}")
    print(f"Sender IP Address: {":".join(str(int(sender_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    print(f"Target MAC Address: {":".join(target_mac[i:i+2] for i in range(0, 12, 2))}")
    print(f"Target IP Address: {":".join(str(int(target_ip[i:i+2], 16)) for i in range(0, 8, 2))}")
    return protocol

def parse_ipv4_packet(hex_data):
    version = hex_data[28:29]
    ihl = hex_data[29:30]
    type_of_service = [30:32]
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
    print(f"Version: HEX: {hex(version)}, INT: {version}")
    print(f"IHL: HEX: {hex(ihl)}, INT: {ihl}")
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
    return protocol

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
    if ether_type == "0x0806":
        parse_arp_packet(hex_data)
    elif ether_type == "0x0800":
        protocol = parse_ipv4_packet(hex_data)
        # TCP
        if (protocol == "0x06"):
            parse_tcp_packet(hex_data)
        elif (protocol == "0x11"):
            prase_udp_packet(hex_data)


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
