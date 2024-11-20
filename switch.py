#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import os
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name
from scapy.utils import mac2str

interfaces_by_name = {}
switch_config = None
root_bridge_ID = None
root_path_cost = None
root_port = None

def read_switch_config(filename):
    switch_config = {'interfaces': []}
    
    with open(filename, 'r') as file:
        lines = file.readlines()
        switch_config['priority'] = int(lines[0].strip())
        
        for line in lines[1:]:
            line = line.strip()
            parts = line.split()
            interface_name = parts[0]
            vlan_or_trunk = parts[1]
            
            interface_info = {'name': interface_name}
            if vlan_or_trunk == 'T':
                interface_info['type'] = 'trunk'
                interface_info['port_state'] = 'BLOCKING'  # for STP support
            else:
                interface_info['type'] = 'access'
                interface_info['vlan'] = int(vlan_or_trunk)
                interface_info['port_state'] = 'LISTENING'  # for STP support
            
            switch_config['interfaces'].append(interface_info)
    
    return switch_config

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def is_trunk(type):
    return type == 'trunk'

def is_access(type):
    return type == 'access'

def is_bpdu_frame(dst_mac):
    return dst_mac == mac2str('01:80:C2:00:00:00')

def forward_frame(received_interface, dest_interface, data, length, vlan_id):
    received_interface_name = get_interface_name(received_interface)
    forward_interface_name = get_interface_name(dest_interface)
    received_data_config = None
    forward_data_config = None

    # save received interface and the next interface
    for i in switch_config['interfaces']:
        if i['name'] == received_interface_name:
            received_data_config = i
        if i['name'] == forward_interface_name:
            forward_data_config = i

    # if we receive on an access interface
    if is_access(received_data_config['type']):
        # and send to an access interface
        if is_access(forward_data_config['type']):
            if received_data_config['vlan'] == forward_data_config['vlan']:
                send_to_link(dest_interface, length, data)
        # and send to a 'LISTENING' trunk interface
        elif is_trunk(forward_data_config['type']) and forward_data_config['port_state'] == 'LISTENING':
            vlan = received_data_config['vlan']
            tag = create_vlan_tag(vlan)
            tagged_data = data[:12] + tag + data[12:]
            send_to_link(dest_interface, len(tagged_data), tagged_data)
    
    # if we receive on a trunk interface
    elif is_trunk(received_data_config['type']):
        # and send to an access interface, if the received VLAN is the same as the one from the interface we send to
        if is_access(forward_data_config['type']) and vlan_id == forward_data_config['vlan']:
            no_tagged_data = data[:12] + data[16:]
            send_to_link(dest_interface, len(no_tagged_data), no_tagged_data)
        # and send to a 'LISTENING' trunk interface
        elif is_trunk(forward_data_config['type']) and forward_data_config['port_state'] == 'LISTENING':
            send_to_link(dest_interface, length, data)

# DST_MAC|SRC_MAC|LLC_LENGTH|LLC_HEADER|BPDU_HEADER|BPDU_CONFIG
def create_bpdu_packet(port):
    dst_mac = mac2str('01:80:C2:00:00:00')
    src_mac = get_switch_mac()
    llc_header = create_llc_header()
    bpdu_header = create_bpdu_header()
    bpdu_config = create_bpdu_config(port)
    llc_length = struct.pack('!H', len(dst_mac) + len(src_mac) + 2 + len(llc_header) + len(bpdu_header) + len(bpdu_config))
    return dst_mac + src_mac + llc_length + llc_header + bpdu_header + bpdu_config

def create_bpdu_header():
    protocol_id = struct.pack('!H', 0x0000)
    protocol_version_id = struct.pack('!B', 0x00)
    bpdu_type = struct.pack('!B', 0x00)
    return protocol_id + protocol_version_id + bpdu_type

def create_bpdu_config(port):
    flags = struct.pack('!B', 0x00) # 1 byte
    root_bridge_id = struct.pack('!Q', root_bridge_ID) # 8 bytes
    root_path_cost_bytes = struct.pack('!I', root_path_cost) # 4 bytes
    bridge_id = struct.pack('!Q', switch_config['priority']) # 8 bytes
    port_id = struct.pack('!H', port) # 2 bytes
    message_age = struct.pack('!H', 1) # 2 bytes
    max_age = struct.pack('!H', 20) # 2 bytes
    hello_time = struct.pack('!H', 2) # 2 bytes
    forward_delay = struct.pack('!H', 15) # 2 bytes
    return flags + root_bridge_id + root_path_cost_bytes + bridge_id + port_id + message_age + max_age + hello_time + forward_delay
    
def create_llc_header():
    dsap = struct.pack('!B', 0x42)
    ssap = struct.pack('!B', 0x42)
    control = struct.pack('!B', 0x03)
    return dsap + ssap + control

def send_bdpu_every_sec():
    while True:
        # Send BDPU every second if necessary
        if (switch_config['priority'] == root_bridge_ID):
            for i in switch_config['interfaces']:
                if is_trunk(i['type']):
                    port_to_send_to = interfaces_by_name[i['name']]
                    data = create_bpdu_packet(port_to_send_to)
                    send_to_link(port_to_send_to, len(data), data)
        time.sleep(1)

def receive_bpdu(data):
    global root_bridge_ID
    global root_path_cost
    global root_port
    bpdu_config = data[21:52]
    bpdu_root_bridge_id = int.from_bytes(bpdu_config[1:9], 'big')
    bpdu_root_path_cost = int.from_bytes(bpdu_config[9:13], 'big')
    bpdu_bridge_id = int.from_bytes(bpdu_config[13:21], 'big')
    bpdu_port_id = int.from_bytes(bpdu_config[21:23], 'big')

    if bpdu_root_bridge_id < root_bridge_ID:
        root_port = bpdu_port_id
        # add 10 to cost because all links are 100Mbps
        root_path_cost = bpdu_root_path_cost + 10

        # if we were the root bridge
        if switch_config['priority'] == root_bridge_ID:
            for i in switch_config['interfaces']:
                # set all trunk interfaces to blocking except the root port
                if i['name'] != get_interface_name(root_port) and is_trunk(i['type']):
                    i['port_state'] = 'BLOCKING'
        
        # update root bridge id
        root_bridge_ID = bpdu_root_bridge_id

        # set root port state to listening
        for i in switch_config['interfaces']:
            if i['name'] == get_interface_name(root_port):
                i['port_state'] = 'LISTENING'

        for i in switch_config['interfaces']:
            # forward BPDU to all other trunk ports
            if i['name'] != get_interface_name(root_port) and is_trunk(i['type']):
                port_to_send_to = interfaces_by_name[i['name']]
                data = create_bpdu_packet(port_to_send_to)
                send_to_link(port_to_send_to, len(data), data)

    # BPDU has the same root_bridge_id as the current root_bridge_id
    elif bpdu_root_bridge_id == root_bridge_ID:
        # BPDU is received on root port and received cost is smaller, update root_path_cost
        if bpdu_port_id == root_port and bpdu_root_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu_root_path_cost + 10
        # BPDU is received on a non-root port and a higher root_path_cost, change BLOCKING port to LISTENING
        elif bpdu_port_id != root_port:
            if bpdu_root_path_cost > root_path_cost:
                for i in switch_config['interfaces']:
                    if i['name'] == get_interface_name(bpdu_port_id) and is_trunk(i['type']) and i['port_state'] == 'BLOCKING':
                        i['port_state'] = 'LISTENING'

    # BPDU from own bridge, setting port to BLOCKING
    elif bpdu_bridge_id == switch_config['priority']:
        for i in switch_config['interfaces']:
            if i['name'] == get_interface_name(bpdu_port_id):
                i['port_state'] = 'BLOCKING'

    else:
        # discard BPDU packet
        return
    
    # if we are the root bridge, set all our ports to LISTENING state
    if switch_config['priority'] == root_bridge_ID:
        for i in switch_config['interfaces']:
            if is_trunk(i['type']):
                i['port_state'] = 'LISTENING'

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    global switch_config
    global root_bridge_ID
    global root_path_cost
    global interfaces_by_name
    global root_port

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
    
    # read current switch configuration
    config_filename = f'configs/switch{switch_id}.cfg'
    if os.path.exists(config_filename):
        switch_config = read_switch_config(config_filename)
        print(f"[INFO] Loaded configuration for switch {switch_id}:")
    else:
        print(f"[ERROR] Configuration file {config_filename} not found.")
        sys.exit(1)

    MAC_Table = {}

    for i in interfaces:
        interfaces_by_name[get_interface_name(i)] = i

    # initialize global variables
    own_bridge_ID = switch_config['priority']
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    root_port = 0

    if own_bridge_ID == root_bridge_ID:
        for i in switch_config['interfaces']:
            i['port_state'] = 'LISTENING'  # designated port

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    for i in interfaces:
        print(get_interface_name(i))

    while True:
        received_interface, data, length = recv_from_any_link()

        if is_bpdu_frame(data[0:6]):
            receive_bpdu(data)
        else:
            dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

            is_unicast = not (dest_mac[0] & 1)

            # Print the MAC src and MAC dst in human readable format
            dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
            src_mac = ':'.join(f'{b:02x}' for b in src_mac)

            print(f'Destination MAC: {dest_mac}')
            print(f'Source MAC: {src_mac}')
            print(f'EtherType: {ethertype}')

            print("Received frame of size {} on interface {}".format(length, received_interface), flush=True)

            # Implement forwarding with learning, VLAN and STP support
            MAC_Table[src_mac] = received_interface

            if is_unicast:
                if dest_mac in MAC_Table:
                    # send unicast frame
                    forward_frame(received_interface, MAC_Table[dest_mac], data, length, vlan_id)
                
                else:
                    # destination not in the mac table, send on all other interfaces
                    for o in interfaces:
                        if o != received_interface:
                            forward_frame(received_interface, o, data, length, vlan_id)

            else:  # multicast or broadcast
                for o in interfaces:
                    if o != received_interface:
                        forward_frame(received_interface, o, data, length, vlan_id)

if __name__ == "__main__":
    main()
