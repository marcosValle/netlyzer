from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from collections import Counter
import requests
from netview import *
from malchk import *
import argparse
from termcolor import colored

class NetAnalysis:
    def __init__(self):
        self.totPkts = 0
        self.srcIP = []
        self.dstIP = []
        self.domains = []
        self.protCnt = {
                "DNS": 0,
                "ICMP": 0,
                }

    def procPkt(self, p):
        self.totPkts += 1
        if IP in p:
            self.srcIP.append(p[IP].src)
            self.dstIP.append(p[IP].dst)
            
            if p.haslayer(DNS):
                self.protCnt["DNS"] += 1
                for x in range(p[DNS].ancount):
                    if p.haslayer(DNSRR):
                        self.domains.append(p[DNSRR][x].rrname)

        if p.haslayer("ICMP"):
            self.protCnt["ICMP"] += 1

    def count(self, data):
        cnt = Counter()
        for d in data:
            cnt[d] += 1
        return cnt

    def mostActiveSrcIPs(self, ips, num):
        return [ip[0] for ip in self.count(ips).most_common(num)]

def parse():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('--check', nargs='+', help='Check against extracted IPs and Domains against external API (vt or abuseipdb)')
    parser.add_argument('--graph', help='Plot IP count graphs', action='store_true')
    parser.add_argument('--filename', help='PCAP file to read from', required=True)
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

***REMOVED***
    banner()
    parser = parse()
    args = parser.parse_args()

    net = NetAnalysis()

    print(colored('=================================', 'green'))
    print(colored('[+] Reading capture file...', 'green'))
    print(colored('(Go grab a cup of coffee, this might take a while)', 'green'))
   
    packets = sniff(offline=args.filename, prn=net.procPkt, store=0)

    print(colored('[+] Done!', 'green'))
    print(colored('=================================', 'green'))

    print(colored('[+] Network summary:', 'green'))
    #print('[+] Total packets: {}'.format(totPkts))
    printProtocols(net.protCnt)
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


