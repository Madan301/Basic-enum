import requests
import whois
import nmap
import socket as s
import pyfiglet

result = pyfiglet.figlet_format("Basic-Enum")
print(result)

def usage():
    print("tool usage -- python3 tool.py")
    print("\n")
    print("[*]Enter 'a' for all four scans")
    print("[*]Enter 's' for sub-domain listing")
    print("[*]Enter 'w' for whois domain information")
    print("[*]Enter 'p' for basic port scanning")
    print("[*]Enter 'd' for basic directory listing")

usage()
def sub_domain_finder(domain_name, sub_domnames):

    print('----Found URLs (sub-domains) ----')
    for subdomain in sub_domnames:

        url = f"https://{subdomain}.{domain_name}"

        try:

            requests.get(url)

            print(f'[+] {url}')

        except requests.ConnectionError:
            pass

        except Exception as e:
            pass


def sub_findr(domain_name):
    with open('subdomain_names1.txt', 'r') as file:
        domains = file.read()
        sub_domains = domains.splitlines()

    sub_domain_finder(domain_name, sub_domains)

def whois_finder(domain):
    print("------Whois domain information------")
    try:
        data = whois.query(domain)
        domain_info_dict = data.__dict__
        print("Domain Name Registrar is => ", domain_info_dict['registrar'])
        print("Domain Name was register on => ", domain_info_dict['creation_date'])
        print("Domain Expires on =>", domain_info_dict['expiration_date'])
        print("Domain Name Status => ", domain_info_dict['status'])
        print("Name servers found => ", list(domain_info_dict['name_servers']))
    except Exception as e:
        print(e)


def port_scanning(domain):
    print("---------basic port scan----------")
    begin = 1
    end = 1000
    a = s.gethostbyname(domain)
    target = a
    print("[*]IP of given domain: ",target)
    print("\n")
    print("[*]Scanning started for first 1000 ports")
    scanner = nmap.PortScanner()
    for i in range(begin, end + 1):
        res = scanner.scan(target, str(i))
        res = res['scan'][target]['tcp'][i]['state']
        if res == 'open':
            print(f'port {i} is {res}.')

def directory_brut(domain):
    print("--------basic directory listing----------")
    new_url = "https://"+domain+"/"
    print(new_url)
    with open('directory_list.txt', 'r') as file:
        direc = file.read()
        directories = direc.splitlines()
    for i in range(len(directories)):
        word = directories[i]
        req_url = new_url+word
#        print(req_url)
        response = requests.get(req_url, headers={"User-Agent": "XY"})
        if response.status_code==200:
            print("valid URL found =>: ",req_url)
        elif response.status_code==300 or response.status_code==301 or response.status_code==302 or response.status_code==303:
            print("Redirecting URL found => ", req_url)

dom = input("Enter the domain name without protocols, EX: 'google.com': ")
mode = input("Enter 'a' for all scan or enter mode according to usage instructions: ")
if mode == 'a':

    sub_findr(dom)
    whois_finder(dom)
    port_scanning(dom)
    directory_brut(dom)
elif mode == 's':
    sub_findr(dom)
elif mode == 'w':
    whois_finder(dom)
elif mode == 'p':
    port_scanning(dom)
elif mode == 'd':
    directory_brut(dom)
else:
    usage()



