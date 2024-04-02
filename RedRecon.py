import os

from colorama import Fore, Back, Style

def domain_to_ip():
    domain = input("Domain: ")
    os.system(f"nslookup {domain}")

def ip_information(ip_address):
    os.system(f"whois {ip_address}")

def subdomains():
    domain = input("Domain: ")
    os.system(f"subfinder -d {domain}")

def ssl_scan():
    ip = input("IP Address: ")
    port = input("Port (Usually 443): ")

    os.system(f"sslscan {ip}:{port}")

def port_scan():
    ip = input("IP Address: ")
    os.system(f"sudo nmap -sSV -Pn --top-ports 1000 {ip}")

def port_scanudp():
    ip = input("IP Address: ")
    os.system(f"sudo nmap -sU -Pn --top ports 200 {ip}")
    
def port_scanmultiplehosts():
    ip = input("IP Address: ")
    hostlist = input("Host List File Path: ")
    os.system(f"sudo nmap -sSV -Pn -iL {hostlist} --top-ports 1000 {ip} -oG NmapScanTCP")

def port_scanudpmultiplehosts():
    ip = input("IP Address: ")
    hostlist = input("Host List File Path: ")
    os.system(f"sudo nmap -sU -Pn -iL {hostlist} --top ports 200 {ip} -oG NmapScanUDP")

def web_scan():
    URL = input("URL Address: ")
    os.system(f"nikto -url {URL}")

def dns_enumeration():
    domain = input("Domain: ")
    os.system(f"dnsenum {domain}")

def vulnerability_scan():
    ip = input("IP address: ")
    os.system(f"nmap --script=vuln {ip}")

def hsts_scan():
    ip = input("IP Address: ")
    port = input("Port (Usually 443): ")
    os.system(f"nmap --script http-security-headers {ip} -p {port}")

def icmp_responsetest():
    ip = input("IP Address: ")
    os.system(f"fping {ip}")
    
def icmp_responsetestmultiplehosts():
    ip = input("IP Address: ")
    hostlist = input("Host List File Path: ")
    os.system(f"fping -f {hostlist} -s -c 1")

def httpmethods_scan():
    ip = input("IP Address: ")
    port = input("Port (Usually 80/443): ")
    os.system(f"nmap --script http-methods {ip} -p {port}")

def httptracemethod_test():
    ip = input("IP Address: ")
    port = input("Port (Usually 80/443): ")
    os.system(f"curl -v -X TRACE {ip}:{port}")

def isakmp_scan():
    ip = input("IP Address: ")
    os.system(f"sudo ike-scan -A -M -v {ip}")

def uncommonport_test():
    ip = input("IP Address: ")
    port = input("Port: ")
    os.system(f"telnet {ip} {port}")

def slowhttpheaders_test():
    URL = input("URL Address: ")
    os.system(f"slowhttptest -u {URL}")

print (Fore.RED + "______         _______")                     
print (Fore.RED + "| ___ |       | | ___ |")                    
print (Fore.RED + "| |_| |___  __| | |_| |___  ___ ___  _ __")  
print (Fore.RED + "|    || _ || _` |    || _ || __| _ || '_ |") 
print (Fore.RED + "| || |  __| |_| | || |  __| |_| |_| | | | |")
print (Fore.RED + "|_| |_|___||__,_|_| |_|___||___|___||_| |_|")
print (Fore.BLACK + "                       by Joseph Burkhalter")

while True:
    print("1. Domain to IP")
    print("2. IP Information")
    print("3. Subdomain Enumeration")
    print("4. SSL Scan")
    print("5. Port Scan TCP Single Host")
    print("6. Port Scan UDP Single Host")
    print("7. Port Scan TCP Multiple Hosts")
    print("8. Port Scan UDP Multiple Hosts")
    print("9. Web Application Scan")
    print("10.DNS Enumeration")
    print("11.Vulnerability Scan")
    print("12.HSTS / Security Headers Scan")
    print("13.ICMP Response Test Single Host")
    print("14.ICMP Response Test Multiple Hosts")
    print("15.HTTP Methods Scan")
    print("16.HTTP TRACE Method Test")
    print("17.ISAKMP (UDP 500) Scan")
    print("18.Uncommon Port Test")
    print("19.Slow HTTP Headers Test")
    option = input("Option: ")

    if option == '1':
        domain_to_ip()
    elif option == '2':
        ip_address = input("Enter the IP address: ")
        ip_information(ip_address)
    elif option == '3':
        subdomains()
    elif option == '4':
        ssl_scan()
    elif option == '5':
        port_scan()
    elif option == '6':
        port_scanudp()
    elif option == '7':
        port_scanmultiplehosts()
    elif option == '8':
        port_scanudpmultiplehosts()
    elif option == '9':
        web_scan()
    elif option == '10':
        dns_enumeration()
    elif option == '11':
        vulnerability_scan()
    elif option == '12':
        hsts_scan()
    elif option == '13':
        icmpresponse_tes()
    elif option == '14':
        icmpresponse_testmultiplehosts()
    elif option == '15':
        httpmethods_scan()
    elif option == '16':
        isakmp_scan()
    elif option == '17':
        httptracemethod_test()
    elif option == '18':
        uncommonport_test()
    elif option =='19':
        slowhttpheaders_test()
    else:
        print("Option Unavailable")
