#!/usr/bin/env python
# coding: utf-8
#
# (c)2017 n0rc

import requests
import hashlib
import json
import sys

from lxml import etree
from requests.exceptions import SSLError
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

### start of config section

# external fritzbox hostname or ip
HOST = 'my.hostname.or.ip'

# ssl port
PORT = 443

# fritzbox login credentials
USERNAME = 'myuser'
PASSWORD = 'mypassword'

# mac to wake up
MAC = '00:C0:1D:C0:FF:EE'

# verify ssl certificates
VERIFY_SSL = True

### end of config section

SID_NOAUTH = '0000000000000000'
URL_LOGIN = 'https://{}:{}/login_sid.lua'.format(HOST, PORT)
URL_DATA = 'https://{}:{}/data.lua'.format(HOST, PORT)


def error_exit(msg):
    print "[error] {}".format(msg)
    sys.exit(1)


def ssl_error_exit():
    error_exit("ssl certificate verification failed")


def get_sid():
    try:
        r = requests.get(URL_LOGIN, verify=VERIFY_SSL)
        t = etree.XML(r.content)
        challenge = t.xpath('//Challenge/text()')[0]
        response = '{}-{}'.format(challenge, hashlib.md5('{}-{}'.format(challenge, PASSWORD).encode('utf-16-le')).hexdigest())
        r = requests.get('{}?username={}&response={}'.format(URL_LOGIN, USERNAME, response), verify=VERIFY_SSL)
        t = etree.XML(r.content)
        return t.xpath('//SID/text()')[0]
    except SSLError:
        ssl_error_exit()


def get_uid(sid):
    try:
        payload = {'sid': sid, 'page': 'netDev'}
        r = requests.post(URL_DATA, data=payload, verify=VERIFY_SSL)
        devs = json.loads(r.content)
        for dev in devs['data']['passive']:
            if dev['mac'] == MAC:
                return dev['UID']
        for dev in devs['data']['active']:
            if dev['mac'] == MAC:
                return dev['UID']
        return ''
    except SSLError:
        ssl_error_exit()


def wake_up(sid, uid):
    try:
        payload = {'sid': sid, 'dev': uid, 'oldpage': 'net/edit_device.lua', 'btn_wake': ''}
        r = requests.post(URL_DATA, data=payload, verify=VERIFY_SSL)
        if '"pid":"netDev"' in r.content:
            return True
        else:
            return False
    except SSLError:
        ssl_error_exit()


if __name__ == '__main__':
    sid = get_sid()
    if sid == SID_NOAUTH:
        error_exit("authentication failed")
    else:
        uid = get_uid(sid)
        if uid:
            if wake_up(sid, uid):
                print "[success] wakeup sent to {}".format(MAC)
            else:
                error_exit("wakeup mac {}".format(MAC))
        else:
            error_exit("unknown mac {}".format(MAC))
