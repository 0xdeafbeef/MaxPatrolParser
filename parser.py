#!/usr/bin/env python
import os
import xml.etree.ElementTree as ET
import csv
import argparse as arp
import gc
import sys

namespaces = {'PT': 'http://www.ptsecurity.ru/reports'}
protocols = {'6': 'TCP', '17': 'UDP'}
port_status = {'0': 'open', '1': 'locked', '2': 'unavailable'}


def mp_parse(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    host_info = []
    appended_info = ['ip', 'fqdn', 'os', 'soft_name', 'soft version', 'soft path', 'port', 'protocol', 'port status',
                     'Vuln id', 'CVSS', 'CVE',
                     'description', 'start time', 'stop_time']
    host_info.append(appended_info)
    vuln_table_creator(root)
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
            vuln_finder(appended_info, soft, host_info, start_time, stop_time)
    return host_info


def get_os_info(host):
    for prod_type in host.findall('PT:scan_objects/PT:soft', namespaces):
        if prod_type.attrib['type'] == '2':
            os = prod_type.find('PT:name', namespaces).text
            os = os + ' ' + prod_type.find('PT:version', namespaces).text
            break
    try:
        os
    except NameError:
        os = None
    return os


def vuln_finder(appended_info, soft, host_info, start_time, stop_time):
    for vulnerabilty in soft.findall('PT:vulners/PT:vulner', namespaces):
        host_info.append(
            appended_info + [vulnerabilty.attrib['id']] + vulners_fast_table[vulnerabilty.attrib['id']] +
            [start_time, stop_time])
        break


vulners_fast_table = dict()


def vuln_table_creator(root):
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
        vulners_fast_table.update({vuln.attrib['id']: vuln_info})


if __name__ == '__main__':
    parser = arp.ArgumentParser(prog='MaxPatrolToCsv')
    parser.add_argument('-p', '--input-path', help='Path to xml file')
    parser.add_argument('-o', '--output', help='Path to output file')
    parser.add_argument('-i', '--ignored-values', help='Ignored values list')
    args = parser.parse_args()
    if args.input_path is None:
        parser.print_help()
        print("[-] -p target parameter required")
        exit(1)
    input_path = args.input_path
    if args.output is None:
        output_path = './output.csv'
    else:
        output_path = args.output
    res = mp_parse(input_path)
    print(sys.getsizeof(vulners_fast_table))
    try:
        os.remove(output_path)
    except:
        pass
    with open(output_path, 'a+', newline='') as file:
        file.write('sep=,\r\n')
        wr = csv.writer(file, quoting=csv.QUOTE_ALL, dialect='excel')
        wr.writerows(res)
