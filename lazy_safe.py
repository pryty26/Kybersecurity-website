import logging
from multiprocessing.reduction import duplicate

from requests.packages import target
from scapy.data import ETHER_TYPES
from volatility3.framework.constants.linux import IP_PROTOCOLS
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, DirModifiedEvent, FileModifiedEvent
import os
import time

def Simple_Watcher(duration=60):
    File = []
    class The_watcher(FileSystemEventHandler):
        def on_modified(self, event):   #self=own event=the 对象

            File.append(f'{event.src_path}changed')
            print(f'{event.src_path}    changed')




    watcher = The_watcher()
    observer = Observer()
    observer.schedule(watcher,'.',recursive=False)
    observer.start()
    time.sleep(duration)
    observer.stop()
    observer.join()
    if File:
        return File
    return'Nothing changed'
def watcher_run(word):
    while True:
        if word.strip().lower() == 'y':
            watcher_result = Simple_Watcher()
            return watcher_result
        if word.strip().lower() == 'n':
            break
        else:
            return 'please write again'
        # 20 minute (smile!)



"""from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # 1. 检查响应是否是HTML
    if "text/html" in flow.response.headers.get("content-type", ""):
        # 2. 在HTML的<body>标签后注入一段JS代码
        html_content = flow.response.get_text()
        injected_script = '<script>alert("页面已被mitmproxy劫持！");</script>'
        
        # 简单的查找替换（实际应用需要更严谨的方法）
        modified_html = html_content.replace('</body>', f'{injected_script}</body>')
        
        # 3. 将修改后的内容设置回响应
        flow.response.set_text(modified_html)
        print("✅ 已成功向页面注入脚本！")"""\

from mitmproxy import http
from urllib.parse import urlparse, parse_qs

xss_payloads = ['<img src=x onerror="alert(1)">']


def request(flow: http.HTTPFlow) -> None:
    return_message = []

    # XSS and SQL tests
    if flow.request.query:
        return_message.append(f'There is total {len(flow.request.query)} queries')
        return_message.append(f"[XSS test] find {len(flow.request.query)} queries\n")

        simple_sql = ['1" or "1"="1', "1' or '1' = '1"]

        for param_name, param_values in flow.request.query.items():
            # XSS test
            for payload in xss_payloads:
                test_query = flow.request.query.copy()
                test_query[param_name] = [payload]
                if len(param_values) == 1:
                    full_test_url = flow.request.url + '?' + '&'.join(f'{k}={v[0]}' for k, v in test_query.items())
                    return_message.append(f"XSS test URL: {full_test_url}\n")

            for p in simple_sql:
                query_copy = querys.copy()
                query_copy[param_name] = [p]
                last_url = "&".join([f'{k}={v[0]}' for k, v in query_copy.items()])
                all_url = f'{flow.request.scheme}://{flow.request.host}{flow.request.path}?{last_url}'
                return_message.append(f"SQL test: {param_name} = {p}\n")
                return_message.append(f"URL: {all_url}\n")

import asyncio
import httpx

async def simple_async_check(client,url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    }
    response = await client.get(url,headers=headers,timeout=15.0)
    return response,url





async def fast_httpx_scan(original_url):
    # Build a simple path scanner using httpx
    common_paths = [
        "/admin", "/phpinfo.php", "/.git", "/backup",
        "/config", "/api", "/test", "/debug"
    ]
    target_urls = []
    return_paths = []
    targets = []
    async_error = []
    original_url1 = None
    # Handle missing protocol
    if not original_url.startswith(('https://','http://')):
        original_url1='http://'+original_url # Use the HTTP protocol as fallback, avoid missing potential target
        original_url='https://'+original_url

    if original_url.endswith('/'):# Avoid double slashes, when we are joining the paths(e.g.:'https://exemple.com//admin')
        original_url=original_url.removesuffix('/')
    else:
        print(
            f" {original_url} has become a yaoguai! \n(Just kidding, it's just missing a /. Scan will continues normally.)")

    target_urls.append(original_url) # first URL added. prepare for path scanning...

    if original_url1:
        if original_url1.endswith('/'):
            original_url1 = original_url1.removesuffix('/')

        target_urls.append(original_url1) # second URL added. prepare for path scanning...


    async with httpx.AsyncClient() as client:

        for path in common_paths:
            for url in target_urls:
                targets_add = f'{url}{path}'
                targets.append(targets_add)

        tasks = [simple_async_check(client,target) for target in targets]

        responses = await asyncio.gather(*tasks,return_exceptions=True)

        for result in responses:
            # check, if result is tuple，and it countain two elements
            if isinstance(result, tuple) and len(result) == 2:
                response, url = result

                # Now we will check is response httpx.Response?
                if isinstance(response, httpx.Response):
                    if response.status_code == 200:
                        return_paths.append(f'{url} exists\n')
                    elif response.status_code == 403:
                        return_paths.append(f'{url} exists but access denied\n')
                    elif response.status_code in [301,302,307,308]:
                        return_paths.append(f'{url} redirect')
                else:
                    async_error.append(f'{url} error: {str(response)}\n')
            else:
                async_error.append(f'{str(result)}')
                pass
        if async_error != []:
            return return_paths,async_error

        return return_paths
########################################################################################
import dpkt
import socket





def analyze_pcap(file_path):  # This function is a Network packet analysis tools


    ETHERTYPES_MAP = {
        # IP协议 - 绝对必要
        0x0800: "IPv4",
        0x86DD: "IPv6",

        # ARP协议 - 网络基础，必须包含
        0x0806: "ARP",

        # VLAN - 企业网络常用
        0x8100: "VLAN",

        # 链路层发现 - 网络设备管理
        0x88CC: "LLDP",
    }

    IP_PROTOCOLS = {
        0: "HOPOPT", 1: "ICMP", 2: "IGMP", 3: "GGP", 4: "IP-in-IP",
        5: "ST", 6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP", 27: "RDP",
        33: "DCCP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH",
        58: "ICMPv6", 88: "EIGRP", 89: "OSPF", 103: "PIM", 108: "IPComp",
        112: "VRRP", 115: "L2TP", 132: "SCTP", 137: "MPLS-in-IP", 255: "RAW",
    }

    return_result = []
    packet_count = 0
    try:
        with open(file_path,'rb') as f:

            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                packet_count += 1
                #count how many packet there have

                eth = dpkt.ethernet.Ethernet(buf)
                return_result.append(f'\nThe serial number of the packet:{packet_count}\n')
                return_result.append(f"Time: {timestamp}")
                return_result.append(f"Source MAC: {eth.src.hex(':')}")
                return_result.append(f"Target MAC: {eth.dst.hex(':')}\n")
                eth_proto = ETHERTYPES_MAP.get(eth.type,f'Unknown:0x{eth.type:04x}')
                return_result.append(f'proto:{eth_proto}\n')

                if isinstance(eth.data, dpkt.ip.IP):


                    ip = eth.data
                    return_result.append(f'Source (SRC) IP:{socket.inet_ntoa(ip.src)}')
                    return_result.append(f'Target (DST) IP:{socket.inet_ntoa(ip.dst)}')
                    ip_proto = IP_PROTOCOLS.get(ip.p,f"Unknown proto:{ip.p}")
                    return_result.append(f'The ip proto:{ip_proto}')
                    return_result.append(f'The total pack lenth:{ip.len}\n')

                    if ip.p == 6 and isinstance(ip.data, dpkt.tcp.TCP):  #double check if ip countains is tcp
                        tcp = ip.data
                        return_result.append(f"The source port: {tcp.sport}")
                        return_result.append(f"target port: {tcp.dport}")
                        return_result.append(f"Flags of TCP: {tcp.flags}\n")

                    if ip.p == 17 and isinstance(ip.data, dpkt.udp.UDP):
                        udp = ip.data
                        return_result.append(f"The source port: {udp.sport}")
                        return_result.append(f"target port: {udp.dport}")
                        return_result.append(f"Flags of UDP: {udp.flags}\n")


        return_result.append(f'There is total:{packet_count} packet')
        return return_result


    except FileNotFoundError:
        return ('error File not found')
    except IOError as a:
        logging.error(f'analyze pcap IOerror:{a}')
        return('error file load error')
    except Exception as e:
        logging.error(f'analyze pcap error:{e}')
        return('Error please try again or use the program later')