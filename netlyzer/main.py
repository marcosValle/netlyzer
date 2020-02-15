from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from collections import Counter
import requests
from netview import *
from malchk import *
import argparse
from termcolor import colored
from datetime import datetime

class NetAnalysis:
    def __init__(self):
        self.verbose = False
        self.protSummary = {
                "DNS":{
                    "firstPkt" : None,
                    "lastPkt" : -1,
                    "data" : 0,
                    "bandwidth" : 0,
                    "count" : 0
                    },
                "ICMP":{
                    "firstPkt" : None,
                    "lastPkt" : -1,
                    "data" : 0,
                    "bandwidth" : 0,
                    "count" : 0
                    }
                }

        self.srcIP = []
        self.dstIP = []
        self.domains = []
        self.totalPkts = 0

    def procPkt(self, p):
        self.totalPkts += 1

        if self.verbose == True:
            print(p.summary())

        if IP in p:
            self.srcIP.append(p[IP].src)
            self.dstIP.append(p[IP].dst)
            
            if p.haslayer(DNS):
                if self.protSummary["DNS"]["count"] == 0:
                    self.protSummary["DNS"]["firstPkt"] = p.time

                self.checkIfLastPkt(p, "DNS")
                self.protSummary["DNS"]["count"] += 1
                self.protSummary["DNS"]["data"] += len(p)

                for x in range(p[DNS].ancount):
                    if p.haslayer(DNSRR):
                        self.domains.append(p[DNSRR][x].rrname)

        if p.haslayer("ICMP"):
            if self.protSummary["ICMP"]["count"] == 0:
                self.protSummary["ICMP"]["firstPkt"] = p.time

            self.checkIfLastPkt(p, "ICMP")

            self.protSummary["ICMP"]["count"] += 1
            self.protSummary["ICMP"]["data"] += len(p)

    def count(self, data):
        cnt = Counter()
        for d in data:
            cnt[d] += 1
        return cnt

    def mostActiveSrcIPs(self, ips, num):
        return [ip[0] for ip in self.count(ips).most_common(num)]

    def checkIfLastPkt(self, p, layer):
        if layer == "DNS" and p.haslayer(layer) and p.time > self.protSummary["DNS"]["lastPkt"]:
            self.protSummary["DNS"]["lastPkt"] = p.time
        if layer == "ICMP" and p.haslayer(layer) and p.time > self.protSummary["ICMP"]["lastPkt"]:
            self.protSummary["ICMP"]["lastPkt"] = p.time

    def getBandwidth(self, protocol):
        if protocol == "DNS":
            timeInterval = datetime.fromtimestamp(self.protSummary["DNS"]["lastPkt"]) - datetime.fromtimestamp(self.protSummary["DNS"]["firstPkt"])
            return self.protSummary["DNS"]["data"]/timeInterval.total_seconds()
        elif protocol == "ICMP":
            timeInterval = datetime.fromtimestamp(self.protSummary["ICMP"]["lastPkt"]) - datetime.fromtimestamp(self.protSummary["ICMP"]["firstPkt"])
            return self.protSummary["ICMP"]["data"]/timeInterval.total_seconds()


def parse():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--check', '-c', nargs='+', help='Check against extracted IPs and Domains against external API (vt or abuseipdb)')
    parser.add_argument('--graph', '-g', help='Plot IP count graphs', action='store_true')
    parser.add_argument('--filename', '-f', help='PCAP file to read from', required=True)
    parser.add_argument('--verbose', '-v', help='Shows packet reading verbosely', action='store_true')
    return parser

def banner():
    print("""
****************************************
*  _   _      _   _                    *
* | \ | | ___| |_| |_   _ _______ _ __ *
* |  \| |/ _ \ __| | | | |_  / _ \ '__|*
* | |\  |  __/ |_| | |_| |/ /  __/ |   *
* |_| \_|\___|\__|_|\__, /___\___|_|   *
*                   |___/              *
*                                      *
* Netlyzer Ver. 0.0.1                  *
* Coded by Marcos Valle (@__mvalle__)  *
* marcosvalle@protonmail.com           *
****************************************""")

if __name__ == '__main__':
    banner()
    parser = parse()
    args = parser.parse_args()

    net = NetAnalysis()

    print(colored('=================================', 'green'))
    print(colored('[+] Reading capture file...', 'green'))
    print(colored('(Go grab a cup of coffee, this might take a while)', 'green'))

    if args.verbose:
        net.verbose = True
    
    packets = sniff(offline=args.filename, prn=net.procPkt, store=0)

    net.protSummary["DNS"]["bandwidth"] = net.getBandwidth("DNS")
    net.protSummary["ICMP"]["bandwidth"] = net.getBandwidth("ICMP")

    print(colored('[+] Done!', 'green'))
    print(colored('=================================', 'green'))

    print(colored('[+] Network summary:', 'green'))

    printProtocols(net.protSummary)
    printTable("Src IP", net.count(net.srcIP))
    printTable("Dst IP", net.count(net.dstIP))
    printTable("Domain", net.count(net.domains))
    print(colored('=================================', 'green'))

    if args.check:
        if 'vt' in args.check:
            print(colored('[+] Checking domains against Virus Total...', 'green'))
            printDomainsChk(checkDomains(list(set(net.domains))))
            print(colored('=================================', 'green'))
        if 'abuseipdb' in args.check:
            print(colored('[+] Checking IPs against Abuse IP DB...', 'green'))
            printIPsChk(checkAbuseIP(net.mostActiveSrcIPs(net.srcIP, 15)))
            print(colored('=================================', 'green'))
    if args.graph:
        print(colored('[+] Plotting fancy graphs...', 'green'))
        viewIPCnt(net.count(net.srcIP))
        print(colored('=================================', 'green'))
