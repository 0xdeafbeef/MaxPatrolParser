#!/usr/bin/env python
import os
import xml.etree.ElementTree as ET
import csv
import argparse as arp
from excel_saver import save_to_excel
import html

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


def mp_parse(input_filename, output_file, flags):
    excel_saving = flags.excel
    level = flags.level
    rows_num = 0
    cve_is_needed = flags.cve
    tree = ET.parse(input_filename)
    root = tree.getroot()
    host_info = []
    appended_info = ['ip', 'fqdn', 'os', 'soft name', 'soft version', 'soft path', 'port', 'protocol', 'port status',
                     'Patrol vulner id', 'Vulner name', 'CVSS', 'CVE', 'Vulnerability rate',
                     'Patrol vulnerability rate',
                     'description', 'how to fix', 'links', 'Scanner name', 'start time', 'stop_time']
    host_info.append(appended_info)
    vuln_table_creator(root)
    if excel_saving is False:
        cwr = csv.writer(output_file, quoting=csv.QUOTE_ALL, dialect='excel')
    for host in root.findall('./PT:data/PT:host', namespaces):
        ip = host.attrib['ip']
        fqdn = host.attrib['fqdn']
        scanner_name = host.find('PT:scanner', namespaces).text
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
            if vuln_finder(appended_info, soft, host_info, start_time, stop_time, scanner_name,
                           level, cve_is_needed) == 0 and not level and not cve_is_needed:
                appended_info += ([None] * 9 + [scanner_name, start_time, stop_time])
                host_info.append(appended_info)
        if excel_saving is False:
            cwr.writerows(host_info)
            rows_num += len(host_info)
            host_info = []
    if excel_saving is False:
        output_file.close()
    return host_info


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


def patrol_level(lvl: str):
    return \
        {'0': 'доступна информация',
         '1': 'низкий уровень',
         '2': 'средний уровень (подозрение)',
         '3': 'средний уровень',
         '4': 'высокий уровень (подозрение)',
         '5': 'высокий уровень'}[lvl]


def vuln_finder(appended_info: list, soft: ET.Element, host_info, start_time: str, stop_time: str, scanner_name: str,
                level: list, cve: bool):
    counter = 0
    for vulnerabilty in soft.findall('PT:vulners/PT:vulner', namespaces):
        if level is None:
            pass
        elif int(vulnerabilty.attrib['level']) not in level:
            continue
        counter += 1
        vulners_part = vulners_fast_table[vulnerabilty.attrib['id']]
        if cve and vulners_part[2] is None:
            continue
        try:
            risk = [risk_level(vulners_part[1], vulnerabilty.attrib['status'])]
        except:
            risk = ['Info']
        patrol_risk = patrol_level(vulnerabilty.attrib['level'])
        risk.append(patrol_risk)
        for l in vulners_part[2]:
            host_info.append(
                appended_info + [vulnerabilty.attrib['id']] + vulners_part[:2] + [l] +
                risk + vulners_part[3:] +
                [scanner_name, start_time, stop_time])
    return counter


vulners_fast_table = dict()


def vuln_table_creator(root: ET, ):
    for vuln in root.findall('./PT:vulners/PT:vulner', namespaces):
        vuln_info = list()
        try:
            vuln_info.append(html.unescape(vuln.find('PT:title', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(vuln.find('PT:cvss', namespaces).attrib['base_score'])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(
                [a for a in [v.attrib['value'] for v in vuln.findall("PT:global_id", namespaces)] if "CVE" in a])
            # if len(vuln.findall("PT:global_id", namespaces)) > 1:
            #     for v in vuln.findall("PT:global_id", namespaces):
            #         print(v.attrib['value'])
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:description', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:how_to_fix', namespaces).text))
        except:
            vuln_info.append(None)
        try:
            vuln_info.append(html.unescape(vuln.find('PT:links', namespaces).text))
        except:
            vuln_info.append(None)
        vulners_fast_table.update({vuln.attrib['id']: vuln_info})


if __name__ == '__main__':
    parser = arp.ArgumentParser(prog='MaxPatrolParser   ')
    parser.add_argument('-p', '--input-path', help='Path to xml file')
    parser.add_argument('-o', '--output', help='Path to output file')
    parser.add_argument('-l', '--level', nargs='+',
                        help='Level of vulnerability. Like -l 1 2 4\n'
                             ' 0 - info\n'
                             ' 1 - low\n'
                             ' 2 - medium (suspicious)\n'
                             ' 3 - medium\n'
                             ' 4 - high (suspicious)\n'
                             ' 5 - high\n')
    parser.add_argument('-e', '--excel', action='store_true', help='Output into xlsx file')
    parser.add_argument('--cve', action='store_true', help='Saves rows in which cve is presented')
    args = parser.parse_args()
    if args.input_path is None:
        parser.print_help()
        print("[-] -p target parameter required")
        exit(1)
    input_path = str(args.input_path)
    if args.level is not None:
        args.level = list(map(lambda x: int(x), args.level))
    if args.output is None:
        output_path = input_path.split('.')[0]
    else:
        output_path = args.output
    if not args.excel:
        output_csv_file = open(output_path + '.csv', 'a+', newline='')
    else:
        output_csv_file = None
    parse_data = mp_parse(input_path, output_csv_file, args)
    print("Xml parsing finished. Got %d rows." % (len(parse_data)))
    if args.excel:
        print('Writing to xlsx..')
        save_to_excel(output_path, parse_data)
