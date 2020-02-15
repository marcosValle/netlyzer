import requests
import json
import yaml

def checkDomains(domains):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    scans = []

    for dom in domains:
        params = {'apikey':getApiKey('vt'), 'resource':dom}
        try:
            response = requests.get(url, params=params)
            scans.append(response.json())
        except Exception as e:
            print("It was not possible to check the {} domain.\nMaybe we hit VT free limit? Try upgrading your API license".format(dom))
            break

        return scans

def checkAbuseIP(ips):
    checkedIPs = {}

    for ip in ips:
        url = 'https://api.abuseipdb.com/api/v2/check'
        querystring = {
                    'ipAddress': ip,
                        'maxAgeInDays': '90'
                        }

        headers = {
                    'Accept': 'application/json',
                        'Key': getApiKey('abuseipdb')
                        }

        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            whitelisted = json.loads(response.text)['data']['isWhitelisted']
            checkedIPs[ip] = whitelisted
        except Exception as e:
            print(e)

    return checkedIPs

def getApiKey(provider):
    with open("/opt/netlyzer/config.yml", 'r') as ymlfile:
        cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)
        if provider == "vt":
            return cfg['api']['vtApiKey']
        if provider == "abuseipdb":
            return cfg['api']['abuseIPDBKey']
