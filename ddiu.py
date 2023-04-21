#!/usr/bin/env python3

import argparse
import ast
import json
import os
import sys
from datetime import datetime

import requests

LIVEBOX_USER_NAME = "admin"
APP_NAME = 'so_sdkut'
LIVEBOX_URL = "http://livebox.home/ws"
ONLINE_URL = "https://api.online.net/api/v1"
DEFAULT_TIMEOUT = 10
IP_KIND = "A"


def parse_args():
    pars = argparse.ArgumentParser(
        prog='ddiu - Dedibox Domain IP Update',
        description='Update Online.net DNS with Livebox IP')

    pars.add_argument('-d', '--debug', action='store_true', default=False, help='Display debug information')
    pars.add_argument('-lp', '--livebox-password', default=os.getenv("LIVEBOX_PWD"), help='Livebox password')
    pars.add_argument('-ok', '--online-key', default=os.getenv("DEDIBOX_API_KEY"), help='Online.net API key')
    pars.add_argument('-dn', '--domain-name', default=os.getenv("DOMAIN_NAME"), help='Domain name')
    pars.add_argument('-sdn', '--sub-domain-name', action='append',
                      help='Sub domains to update. This option can be used multiple times')
    return pars.parse_args()


def get_livebox_ip(arguments):
    session = requests.Session()
    auth_data = {
        "service": "sah.Device.Information",
        "method": "createContext",
        "parameters": {
            "applicationName": APP_NAME,
            "username": LIVEBOX_USER_NAME,
            "password": arguments.livebox_password
        }
    }
    headers = {'Accept': '*/*',
               'Authorization': 'X-Sah-Login',
               'Content-Type': 'application/x-sah-ws-4-call+json'}
    try:
        r = session.post(LIVEBOX_URL, data=json.dumps(auth_data), headers=headers, timeout=DEFAULT_TIMEOUT)
        if args.debug:
            print(r.json())
    except BaseException:
        print("Cannot execute authentication request")
        return -1

    if 'contextID' not in r.json()['data']:
        print("contextID not found in authentication response")
        return -1

    context_id = r.json()['data']['contextID']

    headers = {'Accept': '*/*',
               'Authorization': 'X-Sah ' + context_id,
               'Content-Type': 'application/x-sah-ws-4-call+json; charset=UTF-8',
               'X-Context': context_id}
    try:
        r = session.post(LIVEBOX_URL, data='{"service":"NMC", "method": "getWANStatus", "parameters":{}}',
                         headers=headers, timeout=DEFAULT_TIMEOUT, verify=True)
    except BaseException as e:
        print('getWANStatus query failed.')
        return -1

    r = r.json()
    if arguments.debug:
        print(r)
    if 'data' in r and 'IPAddress' in r['data']:
        return r['data']['IPAddress']

    return -1


def dns_need_to_be_updated(arguments, new_ip):
    found_subdomains = []
    result = False
    domain_name = arguments.domain_name
    headers = {'Authorization': "Bearer " + arguments.online_key}
    r = requests.get(f"{ONLINE_URL}/domain/{domain_name}/zone", headers=headers, timeout=DEFAULT_TIMEOUT)
    for record_result in r.json():
        if arguments.debug and record_result['type'] == IP_KIND and record_result['name'] in arguments.sub_domain_name:
            print(record_result)
        if record_result['type'] == IP_KIND and record_result['name'] in arguments.sub_domain_name:
            found_subdomains.append(record_result['name'])
            if record_result['data'] != new_ip:
                result = True
    for sdn in arguments.sub_domain_name:
        if sdn not in found_subdomains:
            print(f"Sub domain name {sdn} was not found. Exiting.")
            sys.exit(1)
    return result


def update_dns_with_ip(arguments, new_ip):
    if dns_need_to_be_updated(arguments, new_ip):
        content_to_send = []
        for subdomain_name in arguments.sub_domain_name:
            records = [{"name": subdomain_name, "type": IP_KIND, "priority": 0, "ttl": 1800, "data": new_ip}]
            content_to_send += [{"name": subdomain_name, "changeType": "REPLACE", "type": IP_KIND, "records": records}]
        marshalled = json.dumps(content_to_send)
        headers = {'Authorization': "Bearer " + arguments.online_key}
        domain_name = arguments.domain_name
        r = requests.patch(f"{ONLINE_URL}/domain/{domain_name}/version/active", data=marshalled,
                           headers=headers, timeout=20)
        if 200 <= r.status_code < 300:
            print(f"DNS updated successfully with ip: {new_ip}")


if __name__ == "__main__":
    print(f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}: check if IP changed")
    args = parse_args()
    if args.sub_domain_name is None:
        default_sdn_from_env = os.getenv("SUB_DOMAIN_LIST")
        if args.debug:
            print(f"SUB_DOMAIN_LIST = {default_sdn_from_env}")
        if default_sdn_from_env is not None:
            try:
                args.sub_domain_name = ast.literal_eval(os.getenv("SUB_DOMAIN_LIST"))
            except Exception:
                print(f"Cannot parse {default_sdn_from_env}")
        else:
            print("No sub domains in command line or env. Exiting.")
            sys.exit(1)
    if args.domain_name is None:
        print("No domain in command line or env. Exiting.")
        sys.exit(1)
    ip = get_livebox_ip(args)
    if ip == -1:
        print("IP could not be found")
    else:
        update_dns_with_ip(args, ip)
