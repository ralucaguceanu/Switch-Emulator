# Switch Emulator

This project is a Python-based implementation of a Layer 2 Switch Emulator that supports MAC address learning, VLAN tagging, and Spanning Tree Protocol (STP). 

The switch information is stored in a dictionary which has the following keys: 
- interfaces: name (interface name), type (trunk or access), vlan (VLAN id only for access type), port_state (LISTENING or BLOCKING)
- priority (the switch priority)

---

### Forwarding with learning
- unicast: implemented a CAM table as a dictionary (key: Source MAC, value: receiving interface) which dynamically stores the mapping between MAC addresses and the corresponding receiving interface. When receiving a packet, the value for the Source MAC is updated. If a frame's destination MAC address is found in the table, it is forwarded directly to the mapped interface; otherwise, it is flooded.
- multicast: multicast frames are identified by checking if the least significant bit of the Destination MAC address is set. In this scenario, we send the frame on all interfaces except the one on which it was received
- broadcast: the broadcast address (ff:ff:ff:ff:ff:ff) has the least significant bit set and it matches the condition for multicast frames. These two frames are handled similarly.

---

### VLAN support
There are 4 different scenarios, depending on the receiving and forwarding interface type:
- access -> access: received frame is only forwarded between interfaces if they belong to the same VLAN.
- access -> trunk: adding to the received frame the VLAN tag (based on the IEEE 802.1Q Protocol) from the receiving interface configuration and forward the new frame.
- trunk -> access: remove the tag from the received frame and forward it to the access interface if they belong to the same VLAN.
- trunk -> trunk: simply forward the frame.

---

### STP support
Once a second a BPDU frame is created and sent to all trunk interfaces if the current switch is the root bridge. A BPDU frame has the following structure `DST_MAC | SRC_MAC | LLC_LENGTH | LLC_HEADER | BPDU_HEADER | BPDU_CONFIG` and is created similar to the provided documentation. For packing the fields, I used struct.pack with the compatible types: (B - 1 byte, H - 2 bytes, I - 4 bytes, and Q - 8 bytes).

#### BPDU Handling Logic:
- Better Root Bridge Detected (`bpdu_root_bridge_id < root_bridge_ID`):
    - set root_port to the receiving port;
    - set root_path_cost to bpdu_root_path_cost + 10 (100Mbps);
    - if the switch was the root bridge, block all trunk ports except root_port;
    - update root_bridge_ID;
    - set root_port state to LISTENING;
    - forward the updated BPDU on all the other trunk ports.
- Same Root Bridge ID (`bpdu_root_bridge_id == root_bridge_ID`):
    - if received on root_port and the new path cost is lower, update root_path_cost;
    - for non-root ports, set port state on LISTENING (Designated Port) if the sender's path cost is higher.
- BPDU from Own Bridge (bpdu_bridge_id == current switch priority):
    - set port state to BLOCKING to prevent loops.
- Discard BPDU:
    - when none of the above conditions are met.
- Root Bridge Update:
    - if the switch becomes the root bridge, set all trunk ports to LISTENING (Designated Port).
