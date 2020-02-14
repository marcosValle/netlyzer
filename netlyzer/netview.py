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

def printProtocols(protCnt):
    table = PrettyTable(["Protocol", "Count"])
    for prot, count in protCnt.items():
        table.add_row([prot, count])
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

