The main goal of this tool is to quickly analyze a pcap file in order to provide a clear overview of the network and hunt for malicious indicators. Also, it should be extensible as to allow for further development.

# How it works?
Netlyzer was developed from scratch using basically Python3.6, scapy and visualizing modules. It is able to parse a PCAP file and quickly provide the analyst with an overview of the network. It then looks for heuristics that might indicate malicious activities.

# Structure

The tool is divided in the following major components:

1. Network Overview (netover)
2. Network Viewer (netview)
3. Malicious Checker (malchk)

## Network Overview
The `netover` component answers the following questions:

1. How many hosts are there in the network?
2. Which hosts and protocols and ports are most active?
3. List the most used domain names

## Network Viewer
The `netview` component provides visualization of the data parsed from `netover`. Some features provided by this module are:

1. Network diagram

## Malicious Checker
The `malchk` component implements heuristics for malicious behavior detection. For instance:

1. Check the identified domain names and IP addresses against blacklist
2. Look for uncommon ports and protocols

# How could this tool be extended?
Since Netlyzer was developed with the intent of being extended, more features could be easily added, such as:

1. Adding more or private blacklists to check
2. Developping new heuristics for malicious behaviors
