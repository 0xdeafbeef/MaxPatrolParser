#!/usr/bin/env python
import os
import csv
from xml.etree import ElementTree as ET
import argparse as arp
import sys
from excel_saver import save_to_excell

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


def patrol_level(lvl: str):
    return \
        {'0': 'доступна информация',
         '1': 'низкий уровень',
         '2': 'средний уровень (подозрение)',
         '3': 'средний уровень',
         '4': 'высокий уровень (подозрение)',
         '5': 'высокий уровень'}[lvl]

    # if __name__ == '__main__':
    #     parser = arp.ArgumentParser(prog='MaxPatrolParser   ')
    #     parser.add_argument('-p', '--input-path', help='Path to xml file')
    #     parser.add_argument('-o', '--output', help='Path to output file')
    #     parser.add_argument('-l', '--level', nargs='+',
    #                         help='Level of vulnerability. Like -l 1 2 4\n'
    #                              ' 0 - info\n'
    #                              ' 1 - low\n'
    #                              ' 2 - medium (suspicious)\n'
    #                              ' 3 - medium\n'
    #                              ' 4 - high (suspicious)\n'
    #                              ' 5 - high\n')
    #     parser.add_argument('-e', '--excel', action='store_true', help='Output into xlsx file')
    #     parser.add_argument('--cve', action='store_true', help='Saves rows in which cve is presented')
    #     args = parser.parse_args()
    #     if args.input_path is None:
    #         parser.print_help()
    #         print("[-] -p target parameter required")
    #         exit(1)
    #     input_path = args.input_path
    #     if args.level is not None:
    #         args.level = list(map(lambda x: int(x), args.level))
    #     if args.output is None:
    #         output_path = 'output.csv'
    #     else:
    #         output_path = args.output
    #     try:
    #         os.remove(output_path)
    #     except FileNotFoundError:
    #         pass
    #     output_csv_file = open(output_path, 'a+', newline='')
    #     # mp_parse(input_path, output_csv_file, args)
    #     output_csv_file.seek(0)
    #     if args.excel:
    #         save_to_excell(output_path)
    #
    #     sys.exit(0)


def iter_elements_by_name(handle, name):
    events = ET.iterparse(handle, events=("start", "end",))
    _, root = next(events)  # Grab the root element.
    for event, elem in events:
        if event == "end" and elem.tag == name:
            yield elem
            root.clear()  # Free up memory by clearing the root element.


iter_elements_by_name(handle=open('тестовый отчет.xml'), name='data')
