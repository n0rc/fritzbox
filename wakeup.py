#!/usr/bin/env python
# coding: utf-8
#
# (c)2017-2021 n0rc

import argparse
import getpass
import hashlib
import json
import os
import requests
import sys

from lxml import etree
from packaging import version
from requests.exceptions import SSLError
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

SID_NOAUTH = '0000000000000000'


def error_exit(msg):
    print("[error] {}".format(msg))
    sys.exit(1)


def ssl_error_exit():
    error_exit("ssl certificate verification failed")


def get_config(config_file):
    if os.path.isfile(config_file):
        with open(config_file, 'r') as jf:
            config = json.load(jf)
        config['url_login'] = 'https://{}:{}/login_sid.lua'.format(config['host'], config['port'])
        config['url_data'] = 'https://{}:{}/data.lua'.format(config['host'], config['port'])
        return config
    else:
        error_exit("config file not found")


def get_sid(config):
    try:
        password = config['password']
    except:
        password = getpass.getpass()
    try:
        r = requests.get(config['url_login'], verify=config['verify_ssl'])
        t = etree.XML(r.content)
        challenge = t.xpath('//Challenge/text()')[0]
        response = '{}-{}'.format(challenge, hashlib.md5('{}-{}'.format(challenge, password).encode('utf-16-le')).hexdigest())
        r = requests.get('{}?username={}&response={}'.format(config['url_login'], config['username'], response), verify=config['verify_ssl'])
        t = etree.XML(r.content)
        return t.xpath('//SID/text()')[0]
    except SSLError:
        ssl_error_exit()


def get_uid(config, sid, mac):
    try:
        payload = {'sid': sid, 'page': 'netDev', 'xhrId': 'all'}
        r = requests.post(config['url_data'], data=payload, verify=config['verify_ssl'])
        devs = json.loads(r.content)
        for dev in devs['data']['passive']:
            if dev['mac'] == mac:
                return dev['UID']
        for dev in devs['data']['active']:
            if dev['mac'] == mac:
                return dev['UID']
        return ''
    except SSLError:
        ssl_error_exit()


def get_version(config, sid):
    try:
        payload = {'sid': sid, 'page': 'overview'}
        r = requests.post(config['url_data'], data=payload, verify=config['verify_ssl'])
        reply = json.loads(r.content)
        return reply['data']['fritzos']['nspver'].split().pop(0)
    except SSLError:
        ssl_error_exit()
    except KeyError:
        return '0.0'


def wake_up(config, sid, uid):
    try:
        payload = {'sid': sid, 'dev': uid, 'oldpage': 'net/edit_device.lua', 'page': 'edit_device', 'btn_wake': ''}
        vers = get_version(config, sid)
        if version.parse(vers) <= version.parse('7.24'):
            payload['page'] += '2'
        r = requests.post(config['url_data'], data=payload, verify=config['verify_ssl'])
        if r.headers.get("content-type").startswith('application/json'):
            reply = json.loads(r.content)
            try:
                if reply['data']['btn_wake'] == 'ok':
                    return True
            except KeyError:
                pass
            return False
        elif '"pid":"netDev"' in r.text:
            return True
        else:
            return False
    except SSLError:
        ssl_error_exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('device', help='device name (from config file) to sent wakeup to', default='default', nargs='?')
    parser.add_argument('--config', '-c', default='wakeup.json', metavar='wakeup.json', help='use specified config file')
    parser.add_argument('--ssl-no-verify', '-k', action='store_true', help='ignore ssl certificate verification')
    args, _ = parser.parse_known_args()

    config = get_config(args.config)
    config['verify_ssl'] = not args.ssl_no_verify

    if args.device in config['devices']:
        target_mac = config['devices'][args.device]
    else:
        error_exit("unknown device {}".format(args.device))

    sid = get_sid(config)
    if sid == SID_NOAUTH:
        error_exit("authentication failed")
    else:
        uid = get_uid(config, sid, target_mac)
        if uid:
            if wake_up(config, sid, uid):
                print("[success] wakeup sent to {}".format(target_mac))
            else:
                error_exit("something went wrong while sending wakeup to {}".format(target_mac))
        else:
            error_exit("unknown mac {}".format(target_mac))
