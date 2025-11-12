import logging
import random
from concurrent.futures import ThreadPoolExecutor
import requests
from flask import render_template
import time

from fontTools.misc.eexec import encrypt
from scapy.all import*
from datetime import datetime

common_subdomains = [
    "www", "mail", "ftp", "localhost", "webmail", "admin", "blog",
    "dev", "test", "api", "shop", "support", "help", "cdn", "cloud",
    "email", "files", "forum", "git", "host", "mobile", "news",
    "portal", "secure", "ssl", "static", "store", "vpn", "web"
]

def check_subdomain(subdomain,target_domain):
    headers = {
        'User-Agent': random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ])
    }
    for protocol in ["https","http"]:
        full_domain = f"{protocol}://{subdomain}.{target_domain}"
        try:
            response = requests.get(full_domain, headers=headers, timeout=3)
            if response.status_code < 400:
                print(f"✅ Find: {full_domain} (The status code: {response.status_code})")
                return full_domain
        except Exception as e:
            continue
    return False

def fast_subdomain_check(target_domain):
    try:
        found_subdomains = []
        worker_numbers=random.randint(20,30)
        with ThreadPoolExecutor(max_workers=worker_numbers) as f:
            futures = [f.submit(check_subdomain,sub,target_domain)for sub in common_subdomains]

            for future in futures:
                result = future.result()
                if result:
                    found_subdomains.append(result)
            return found_subdomains
    except Exception as e:
        print(f'error:{e}')


def route_and_subdomaincheck(target_domain):
    def check_path(domain, original_path):
        #check the single route
        headers = {
            'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            ])
        }
        path = original_path.lstrip('/')
        #path = the path that user input and removed the last/
        target_url = f"{domain}/{path}"
        try:
            response = requests.get(target_url, headers=headers, timeout=3, allow_redirects=False)#its pretty dangerouse(allow_redirects=False) but……
            urls_status_code = response.status_code
            return target_url,urls_status_code

        except Exception as e:
            pass
        return None


    def route_check(target_domain):

        try:
            if not target_domain:
                return render_template("PATHS_AND_DOMAINS_CHECK.html", result="The domain name can't be none")

            found_domains = fast_subdomain_check(target_domain)

            if not found_domains:
                # if not found anything then check the main
                found_domains = [f"https://{target_domain}", f"http://{target_domain}"]

            # routes
            ADMIN_PATHS = ['admin', 'login', 'wp-admin', 'dashboard', 'console']
            SENSITIVE_PATHS = ['config', 'backup', 'database', '.env', 'config.php']
            SYSTEM_PATHS = ['phpmyadmin', 'cpanel', 'robots.txt', '.git']

            all_paths = ADMIN_PATHS + SENSITIVE_PATHS + SYSTEM_PATHS

            paths_cant_in = []
            found_paths = []
            with ThreadPoolExecutor(max_workers=25) as f:
                for domain in found_domains:
                    futures = [f.submit(check_path,domain,path) for path in all_paths]

                    for future in futures:
                        result = future.result()
                        if result:
                            domain_result,the_status_code=result
                            if the_status_code == 200:
                                found_paths.append(domain_result)
                            elif the_status_code in [401,403]:
                                paths_cant_in.append(domain_result)
            if found_domains == [f"https://{target_domain}", f"http://{target_domain}"]:
                return (f"finded {len(found_paths)} paths.The paths are:{found_paths}.And these paths exist, but access is prohibited{paths_cant_in} ")

            if found_paths:
                return (f"finded {len(found_domains)} subdomains, "
                        f"and {len(found_paths)} paths.Domains are:{found_domains},"
                        f"and the paths are:{found_paths}.And these paths exist, but access is prohibited{paths_cant_in} ")
            if found_domains != [f"https://{target_domain}", f"http://{target_domain}"]:
                return (
                    f"finded {len(found_domains)} subdomains, "
                    f"and {len(found_paths)} paths.Domains are:{found_domains},and the paths are:{found_paths}."
                    f"And these paths exist, but access is prohibited{paths_cant_in} ")

            else:
                return('Wrong')
            #mother XXXXXXX black me qswl
            #this cost me……five hour!!!
        except Exception as e:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logging.error(f'time:{current_time},\n,error: {e}')
            return('error')
        #youyoucangtian heboyuwo 2hours=None
    return route_check(target_domain)
#
#<img src=1a onerror="alert(document.cookie)">
#上面那个就是该S的XSS攻击，万分小心！
#UNION SELECT table_name,2,3 FROM information_schema.tables --
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#
#params
def sql_check(url):
    try:
        headers = {
            'User-Agent':
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        Union_check = [
            "1' UNION SELECT table_name,2,3 FROM information_schema.tables --",
            "1' UNION SELECT column_name,2,3 FROM information_schema.columns --"
                       ]
        Boolean_check = [
            '1',
            "1' or '1'='1",
            "1' and '1'='1",
            "1' or '1'='2",
        ]
        Time_check = [
            "1' or sleep(5)--",
            "1' and sleep(5)--"
        ]

        Sql_bugs = []
        normal_page = None
        if Sql_bugs == []:
            for p in Boolean_check:
                res = requests.get(url,params={'id':p},headers=headers,timeout=10)
                if res.status_code == 200:
                    if p=='1':
                        normal_page = res.text
                    elif normal_page != None:
                        if res.text != normal_page:
                            Sql_bugs.append(f'The website have Boolean blinds bug:{p}')

        Union_bug_finded = False
        Union_bug_maybe_finded = False

        if Union_bug_finded == False:
            for pa in Union_check:
                res = requests.get(url,params={'id':pa},headers=headers,timeout=10)
                if res.status_code == 200:
                    if res.text != normal_page and normal_page != None:
                        if "mysql" in res.text.lower() or "error" in res.text.lower():
                            Union_bug_finded = True
                            Sql_bugs.append(f'Union query vulnerability exists: {pa}')
                        elif any(word in res.text.lower() for word in ["users", "admin", "password"]):
                            Union_bug_finded = True
                            Sql_bugs.append(f'Union query vulnerability exists: {pa}')
                        else:
                            if Union_bug_maybe_finded == False:
                                Sql_bugs.append(f'maybe Union query vulnerability exists(page change)but its uncertain{pa}')
                                Union_bug_maybe_finded = True


        Time_bug_finded = False

        if Time_bug_finded == False:
            for pay in Time_check:
                start_time = time.time()
                try:
                    res = requests.get(url, params={'id': pay}, headers=headers, timeout=15)
                    end_time = time.time()
                    response_time = end_time - start_time
                    if response_time >= 5:
                        Sql_bugs.append(f'Time Blind bug finded: {pay}')
                        Time_bug_finded = True
                        break
                except requests.exceptions.Timeout:
                    Sql_bugs.append(f'outtime!: {pay}')
                    Time_bug_finded = True
                    break



        if Sql_bugs != []:
            return Sql_bugs
        else:
            return None
    except TypeError:
        return 'wrong url please wrote again'
    except Exception as e:
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logging.error(f'time:{current_time},\n,error: {e}')
        return 'Error!Please use sql check later.'



def packet_check(packet):

    PROTOCOLS = {
        0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP",
        5: "ST", 6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP", 27: "RDP",
        33: "DCCP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
        58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 108: "IPComp",
        112: "VRRP", 115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP", 255: "RAW",
    }

    if packet.haslayer(IP):
        # ip layer
        packet_src_ip = packet[IP].src #where ip does it come
        packet_dst_ip = packet[IP].dst
        packet_proto = packet[IP].proto# get the proto(协议!)code
        if packet_proto in PROTOCOLS:#if the code is in protocols
            packet_name = PROTOCOLS[packet_proto]#packet name = The name corresponding to the code

            if packet.haslayer(TCP):
                src_port=packet[TCP].sport
                dst_port=packet[TCP].dport
                if packet.haslayer(Raw):
                    raw_loaded = packet[Raw].load
                    try:
                        text = raw_loaded.decode('utf-8',errors='ignore')

                        print(f'\n{packet_name}:{packet_src_ip} ---> {packet_dst_ip} and port:{src_port}-->{dst_port}\nThe message:\n')
                        print(text)
                        return (f'\n{packet_name}:{packet_src_ip} ---> {packet_dst_ip} and port:{src_port}-->{dst_port}\nThe message:\n{text}')
                    except:
                        print('decoding failled')
                        pass
                return (f'{packet_name}:{packet_src_ip} ---> {packet_dst_ip} and port:{src_port}-->{dst_port}')
            if packet.haslayer(UDP):
                src_port=packet[UDP].sport
                dst_port=packet[UDP].dport
                return (f'{packet_name}:{packet_src_ip} ---> {packet_dst_ip} and port:{src_port}-->{dst_port}')
            return (f'{packet_name}:{packet_src_ip} ---> {packet_dst_ip}')
        else:
            return (f'Unknown protocol:{packet_proto}:{packet_src_ip} ---> {packet_dst_ip}')

    else:
        return None
def simple_sniff(count=10, filter='host 127.0.0.1'):
    packets=sniff(count=count,filter=filter)

    results = []
    for packet in packets:
        result = packet_check(packet)
        if result:
            results.append(result)

    for result in results:
        print(result,'\n')
    return results
import time
print('开始')

s_time = time.time()
for i in range(10000):
    print(i)
end = time.time()
a=end - s_time
print(f"time={a:.2f}")


