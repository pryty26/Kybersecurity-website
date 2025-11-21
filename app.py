import sqlite3
import threading
from lazy_safe import Simple_Watcher
import logging
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import os
import json
import hashlib
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import random
import time
from functools import wraps
from pygments.lexer import default
from scapy.all import *
from all_functions import login_check, verify_the_password, commonplace_text, white_ip_check, add_user
from safe_functions import route_and_subdomaincheck, sql_check, simple_sniff
from datetime import datetime
import sys
from logging.handlers import RotatingFileHandler


app = Flask(__name__)

app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
#Set secret key





handler = RotatingFileHandler(
    'honeypot.log',
    maxBytes=10*1024*1024,  # 10MB
    backupCount=3
)

logging.basicConfig(
    level=logging.WARNING,
    format = '%(asctime)s - %(message)s',
    handlers=[handler]
)


limiter = Limiter(
    app = app,
    key_func = get_remote_address,
    default_limits = ['3600 per minute']
)


#Preventing DDOS attacks

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response  #steal! (this headers is present by deepseek,smile)

@app.route('/')
#The home of website
@limiter.limit('240 per minute')
def web_home():
    return render_template('home.html')

@app.route('/The_cookies')
@limiter.limit('20 per minute')
def the_cookies():
    return render_template('The_cookies.html')


@app.route('/nuke/mh', methods=['POST'])
@login_check
@white_ip_check
@limiter.limit('5 per minute')
def emergency_nuke():

    conn = sqlite3.connect('super_password.db')

    cursor = conn.execute('SELECT password FROM all_passwords')

    SUPER_PASSWORD = cursor.fetchone()

    if request.form.get('password') != SUPER_PASSWORD:
        logging.warning(f"NUKE ERROR!!! - IP: {request.remote_addr} - USER: {session.get('username')}")
        time.sleep(1)
        return render_template('nuke_mh.html', result='error')

    def nuclear_shutdown():
        logging.error("Error!Server will close soon……")
        time.sleep(3)
        logging.error(f"NUKE PASSWORD COLLECT!!! - IP: {request.remote_addr} - USER: {session.get('username')}")
        logging.error("💀 SERVER CLOSED!!!")
        sys.exit(1)  # 使用特殊退出代码

    threading.Thread(target=nuclear_shutdown).start()
    return render_template('nuke_mh.html', result='success')


@app.route('/watcher/mh', methods=['GET', 'POST'])
@login_check
@white_ip_check
def watcher():
    if request.method == 'POST':
        duration_str = request.form.get('duration')

        try:
            duration = int(duration_str)
            if 3 < duration < 100000:

                result = Simple_Watcher(duration)
                return render_template('watcher_mh.html', result=result)
            else:
                return render_template('watcher_mh.html',result="The duration should be to 4s to 99999s")
        except Exception as e:
            logging.error(f'/watcher/mh had a error:{e}')
        return render_template('watcher_mh.html',result="Error")
    return render_template('watcher_mh.html')



@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login_page_advanced():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    logging.warning(f"Advanced admin page accessed - IP: {client_ip} | Time: {current_time} | UA: {user_agent}")

    if request.method == 'POST':
        ad_username = request.form.get('ad_username')
        ad_password = request.form.get('ad_password')
        if ad_username and ad_password:
            logging.warning(
                f"Login attempt on advanced admin - IP: {client_ip} | Username: {ad_username} | Password: {ad_password}")
        return render_template('JEESUS.html')  # Good karma +999(yeah!)!!!

    return render_template('adminlogin.html')



@app.route('/admin',methods=['GET','POST'])
def admin_login_page():
    client_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', 'Unknown')
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # remember!
    logging.warning(f"This guy has on the admin page - IP: {client_ip} | Time: {current_time} | UA: {user_agent}")
    if request.method == 'POST':
        ad_username = request.form.get('ad_username')
        ad_password = request.form.get('ad_password')
        if ad_username and ad_password:
            logging.warning(f"He trys to login in the admin page - IP: {client_ip} | username: {ad_username} | password: {ad_password}")
            return render_template('admin_login.html',result="Login success!")

    return render_template('admin_login.html')


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('20 per minute,600 per hour')
def login_page():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # check the password
        result = verify_the_password(username, password)
        success_value = result.get('success')
        if success_value is True or success_value == "True":
            session['user_id'] = secrets.token_hex(32)
            session['username'] = f'{username}'
            session['login_time'] = time.time()
            return redirect(url_for('security_tools'))
        elif result.get('success') == 'warning':
            logging.warning(f'The IP:{request.remote_addr} is{result.get('message')}')
            return redirect('/admin/login')
        else:
            return render_template('login.html', error="Login False")

    return render_template('login.html')  # This line needs to be the last one

IP_PORT_SCANNER_VARIANTS = [
    'ipportscanner',
    'ipportscan',
    'portscanner',
    'portscan',
    'ipscanner',
    'ipportsscanner',
    'ipportsscan',
    'portsscanner',
    'portsscan',
]


PATHS_AND_DOMAINS_CHECK_VARIANTS = [
    'paths_and_domains_check',
    'pathsanddomainscheck',
    'pathcheck',
    'domaincheck',
    'pathscheck',
    'domainscheck',
    'pathanddomaincheck',
    'pathsanddomaincheck',
    'pathsanddomainschk',
    'pathsdomainscheck',
    'pathdomaincheck',
    'pathdomainchecks',
]

SQL_CHECK_VARIANTS = [
    'sqlcheck',
    'sqlchecker',
    'sqltest',
    'sqldetection',
    'sqlscan',
    'sqlscanner',
    'sqlinjectioncheck',
    'sqlvulncheck',
    'sqlinjecttest',
    'sqlsecuritycheck'
]

@app.route('/security_tools',methods=['GET', 'POST'])
@login_check
@limiter.limit('30 per minute')
def security_tools():
    if request.method == 'POST':
        Attack_form = request.form.get('Attack_form')
        Normal_form = commonplace_text(Attack_form)

        if Normal_form in IP_PORT_SCANNER_VARIANTS:
            return render_template('ipportscan.html')
        if Normal_form in PATHS_AND_DOMAINS_CHECK_VARIANTS:
            return render_template('PATHS_AND_DOMAINS_CHECK.html')
        if Normal_form in SQL_CHECK_VARIANTS:
            return render_template('sql_check.html')
        else:
            return render_template('security-tools.html',result='wrong security tools ,available_tools: [ip port scanner, paths and domains check]')

    return  render_template('security-tools.html')
#bro u didnt finished this remember!


@app.route('/SQL_CHECK',methods=['GET','POST'])
@login_check
@limiter.limit('15 per minute')
def sql_check_route():
    if request.method == 'POST':
        target_url = request.form.get('target_url')
        if len(target_url) > 10000:
            return render_template('sql_check.html',result='The url is to long')
        sql_result = sql_check(target_url)
        if sql_result == None:
            return render_template('sql_check.html',result='There is no bugs')
        else:
            return render_template('sql_check.html', result=sql_result)
    return render_template('sql_check.html')

@app.route('/PATHS_AND_DOMAINS_CHECK', methods=['GET', 'POST'])
@login_check
@limiter.limit('15 per minute')
def route_and_subdomain_check():
    if request.method == 'POST':
        target_domain = request.form.get('target_domain')
        the_result = route_and_subdomaincheck(target_domain)
        if the_result == 'Wrong':
            return render_template('PATHS_AND_DOMAINS_CHECK.html')
        else:
            return render_template('PATHS_AND_DOMAINS_CHECK.html', result=the_result)

    return render_template('PATHS_AND_DOMAINS_CHECK.html')




@app.route('/ipportscan',methods=['GET','POST'])
@login_check
@limiter.limit('20 per minute')
def portscan():

    if request.method == "POST":
        try:
            target_ip = request.form.get('target_ip')
            if not target_ip:
                return render_template('ipportscan.html',result="You need to write the ip")

            input_target_port = request.form.get('target_ports')
            if not input_target_port:
                target_ports = [80, 443, 22, 21, 53]#default port
            else:
                if ',' in input_target_port:
                    target_ports= [int(port.strip())for port in input_target_port.split(',')]
                else:
                    target_ports = [int(input_target_port)]
            for port in target_ports:
                if port<1 or port>65535:
                    return render_template('ipportscan.html',result="The port can't be bigger then 65535 or smaller then 1(port should be 1-65535)")

            if len(target_ports) > 50:
                return render_template('ipportscan.html',result="You cannot scan too many ports at once (maximum 50)")

            scan_result = []
            for port in target_ports:
                src_port = random.randint(50000, 65535)
                ip_layer = IP(dst=target_ip)#where do u send IP层
                tcp_layer = TCP(sport=src_port,dport=port,flags="S")#how which port and flag=syn 更低




                response = sr1(ip_layer / tcp_layer, timeout=1, verbose=0)

                if response:
                    if response.haslayer(TCP):
                        tcp_layer = response.getlayer(TCP)
                        if tcp_layer.flags == 0x12:  # SYN-ACK syn=0x2 ack=0x10
                            scan_result.append(f"Port {port}: Open")
                        elif tcp_layer.flags == 0x14:  # RST-ACK rst=0x4 ack=0x10
                            scan_result.append(f"Port {port}: closed")
                else:
                     scan_result.append(f"Port {port}: Filtered/No response")
            scan_result_text = '<br>'.join(scan_result)
            return render_template('ipportscan.html',result=scan_result_text)
        except ValueError:
            return render_template('ipportscan.html',result='Your port name or ip name is wrong!')
        except TimeoutError:
            return render_template('ipportscan.html',result='scantime Timeout')
        except Exception as e:
            return render_template('ipportscan.html',result=f'error:{e}')
    return render_template('ipportscan.html')

if __name__ == '__main__':
    try:
        app.run(debug=False, host='0.0.0.0', port=5000)

    except Exception as e:
        print(f'error:{e}')
###
####
#####

