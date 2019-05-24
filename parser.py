#!/usr/bin/python
import xml.etree.ElementTree as ET
import xlwt
import sys

namespaces = {'PT': 'http://www.ptsecurity.ru/reports'}
protocols = {'6': 'TCP', '17': 'UDP'}


def mp_parse(filename):
    with open(filename, 'r') as xml_file:
        xml_tree = ET.parse(xml_file)
        xml_root = xml_tree.getroot()
        hosts_list = []
        for host in xml_root.findall("./PT:data/PT:host", namespaces):
            soft_list = []
            host_dict = {'soft': [], 'ip': host.attrib['ip']}
            for soft in host.findall('PT:scan_objects/PT:soft', namespaces):
                vulners_list = []
                soft_dict = {'vulners': [], 'name': soft.find('PT:name', namespaces).text,
                             'port': soft.attrib['port'] + '/' + protocols[soft.attrib['protocol']]}
                for vulner in soft.findall('PT:vulners/PT:vulner', namespaces):
                    vulner_dict = {}
                    vulner_id = vulner.attrib['id']
                    vulner_dict['reliability'] = vulner.attrib['status']
                    for vulner_descr in xml_root.findall("./PT:vulners/PT:vulner", namespaces):
                        if vulner_id == vulner_descr.attrib['id']:
                            if vulner_descr.find('PT:cvss', namespaces) is not None and \
                                    vulner_descr.find('PT:cvss', namespaces).attrib['base_score'] != '0.0':
                                vulner_dict['id'] = vulner_id
                                vulner_dict['title'] = vulner_descr.find('PT:title', namespaces).text
                                vulner_dict['base_score'] = vulner_descr.find('PT:cvss', namespaces).attrib[
                                    'base_score']
                                vulner_dict['base_score_decomp'] = vulner_descr.find('PT:cvss', namespaces).attrib[
                                    'base_score_decomp']
                                vulner_dict['description'] = vulner_descr.find('PT:description', namespaces).text
                                vulner_dict['short_description'] = vulner_descr.find('PT:short_description',
                                                                                     namespaces).text
                                vulner_dict['how_to_fix'] = vulner_descr.find('PT:how_to_fix', namespaces).text
                                try:
                                    vulner_dict['cve'] = \
                                        vulner_descr.find('PT:global_id[@name="CVE"]', namespaces).attrib['value']
                                except:
                                    vulner_dict['cve'] = 'None'
                                try:
                                    vulner_dict['links'] = vulner_descr.find('PT:links', namespaces).text
                                except:
                                    vulner_dict['links'] = 'None'
                                vulners_list.append(vulner_dict)
                if len(vulners_list):
                    soft_dict['vulners'] = sorted(vulners_list, key=lambda x: float(x['base_score']), reverse=True)
                    soft_list.append(soft_dict)
            if len(soft_list):
                host_dict['soft'] = soft_list
                hosts_list.append(host_dict)
    return hosts_list


if __name__ == '__main__':
    mp_parse('test.xml')
