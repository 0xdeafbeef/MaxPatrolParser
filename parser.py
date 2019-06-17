#!/usr/bin/env python
import os
import xml.etree.ElementTree as ET
import csv
import argparse as arp
import sys
from xlsxwriter.workbook import Workbook

namespaces = {'PT': 'http://www.ptsecurity.ru/reports'}
protocols = {'6': 'TCP', '17': 'UDP'}
port_status = {'0': 'open', '1': 'locked', '2': 'unavailable'}


def risk_level(cvss, reliability):
    cvss = float(cvss)
    if int(reliability) == 0:
        if cvss >= 9:
            return 'Critical'
        elif cvss >= 7 and cvss < 9:
            return 'High'
        elif cvss > 4 and cvss < 7:
            return 'Medium'
        else:
            return 'Low'
    elif int(reliability) == 1:
        if cvss >= 9:
            return 'Critical (Suspicious)'
        elif cvss >= 7 and cvss < 9:
            return 'High (Suspicious)'
        elif cvss > 4 and cvss < 7:
            return 'Medium (Suspicious)'
        else:
            return 'Low (Suspicious)'


def mp_parse(filename, output_file, flags):
    level = flags.level
    cve_is_needed = flags.cve
    tree = ET.parse(filename)
    root = tree.getroot()
    host_info = []
    appended_info = ['ip', 'fqdn', 'os', 'soft name', 'soft version', 'soft path', 'port', 'protocol', 'port status',
                     'Patrol vulner id', 'Vulner name', 'CVSS', 'CVE',
                     'description', 'how to fix', 'links', 'start time', 'stop_time']
    host_info.append(appended_info)
    vuln_table_creator(root)
    cwr = csv.writer(output_file, quoting=csv.QUOTE_ALL, dialect='excel')
    for host in root.findall('./PT:data/PT:host', namespaces):
        ip = host.attrib['ip']
        fqdn = host.attrib['fqdn']
        start_time = host.attrib['start_time']
        stop_time = host.attrib['stop_time']
        os = get_os_info(host)
        for soft in host.findall('PT:scan_objects/PT:soft', namespaces):
            appended_info = list()
            appended_info.append(ip)
            appended_info.append(fqdn)
            appended_info.append(os)
            appended_info.append(soft.find('PT:name', namespaces).text)
            try:
                appended_info.append(soft.find('PT:version', namespaces).text)
            except:
                appended_info.append(None)
            try:
                appended_info.append(soft.find('PT:path', namespaces).text)
            except:
                appended_info.append(None)
            try:
                appended_info.append(soft.attrib['port'])
            except:
                appended_info.append(None)
            try:
                appended_info.append(protocols[soft.attrib['protocol']])
            except:
                appended_info.append(None)
            try:
                appended_info.append(port_status[soft.attrib['port_status']])
            except:
                appended_info.append(None)
            # finds cve and cvss if exists, else sets None
            if vuln_finder(appended_info, soft, host_info, start_time, stop_time,
                           level, cve_is_needed) == 0 and level == 0:
                appended_info += ([None] * 7 + [start_time, stop_time])
                host_info.append(appended_info)
        cwr.writerows(host_info)
        host_info = []


def get_os_info(host):
    for prod_type in host.findall('PT:scan_objects/PT:soft', namespaces):
        if prod_type.attrib['type'] == '2':
            os_name = prod_type.find('PT:name', namespaces).text
            os_name = os_name + ' ' + prod_type.find('PT:version', namespaces).text
            break
    try:
        os_name
    except NameError:
        os_name = None
    return os_name


def vuln_finder(appended_info: list, soft: ET.Element, host_info, start_time: str, stop_time: str, level: list,
                cve: bool):
    counter = 0
    for vulnerabilty in soft.findall('PT:vulners/PT:vulner', namespaces):
        if len(level) == 1 and (int(vulnerabilty.attrib['level']) < int(level[0])):
            continue
        elif vulnerabilty.attrib['level'] not in level:
            continue
        counter += 1
        vulners_part = vulners_fast_table[vulnerabilty.attrib['id']]
        if cve and vulners_part[2] is None:
            continue
        try:
            risk = risk_level(vulners_part[1], vulnerabilty.attrib['status'])
        except:
            risk = 'Info'
        vulners_part.insert(3, risk)
        host_info.append(
            appended_info + [vulnerabilty.attrib['id']] + vulners_part +
            [start_time, stop_time])
    return counter


vulners_fast_table = dict()


def vuln_table_creator(root: ET, ):
    for vuln in root.findall('./PT:vulners/PT:vulner', namespaces):
        vuln_info = list()
        try:
            vuln_info.append(vuln.find('PT:title', namespaces).text)
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:cvss', namespaces).attrib['base_score'])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:global_id', namespaces).attrib['value'])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:description', namespaces).text)
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:how_to_fix', namespaces).text)
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:links', namespaces).text)
        except:
            vuln_info.append(None)
        vulners_fast_table.update({vuln.attrib['id']: vuln_info})


if __name__ == '__main__':
    parser = arp.ArgumentParser(prog='MaxPatrolParser   ')
    parser.add_argument('-p', '--input-path', help='Path to xml file')
    parser.add_argument('-o', '--output', help='Path to output file')
    parser.add_argument('-l', '--level', nargs='+',
                        help='Level of vulnerability. 0 - info\n'
                             ' 1 - low\n'
                             ' 2 - medium (suspicious)\n'
                             ' 3 - medium\n'
                             ' 4 - high (suspicious)\n'
                             ' 5 - high\n')
    parser.add_argument('--cve', action='store_true')
    args = parser.parse_args()
    if args.input_path is None:
        parser.print_help()
        print("[-] -p target parameter required")
        exit(1)
    if args.level is None:
        args.level = [0]
    input_path = args.input_path
    if args.output is None:
        output_path = './output.csv'
    else:
        output_path = args.output
    try:
        os.remove(output_path)
    except:
        pass
    file = open(output_path, 'a+', newline='')
    mp_parse(input_path, file, args)
    sys.exit(0)
