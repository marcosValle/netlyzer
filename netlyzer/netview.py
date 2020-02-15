import plotly
from prettytable import PrettyTable

def viewIPCnt(cnt):
    xData = []
    yData = []

    for ip, cnt in cnt.most_common():
        xData.append(ip)
        yData.append(cnt)

    plotly.offline.plot({
        "data":[plotly.graph_objs.Bar(x=xData, y=yData)]
        })

def printTable(column, cnt):
    if not cnt:
        return

    table = PrettyTable([column, "Count"])
    for col, count in cnt.most_common(10):
        table.add_row([col, count])
    print(table)

def printProtocols(protSummary):
    table = PrettyTable(["Protocol", "Pkt Count", "Traffic (B)", "Bandwidth (Bps"])
    for prot, desc in protSummary.items():
        table.add_row([prot, desc["count"], desc["data"], desc["bandwidth"]])
    print(table)

def printDomainsChk(scans):
    if not scans:
        return
    table = PrettyTable(["URL", "Result"])
    for scan in scans:
        table.add_row([scan['url'], "{}/{}".format(scan['positives'], scan['total'])])
    print(table)

def printIPsChk(checkedIPs):
    if not checkedIPs:
        return
    table = PrettyTable(["IP", "Whitelisted"])
    for ip, isWhitelisted in checkedIPs.items():
        table.add_row([ip, isWhitelisted])
    print(table)

