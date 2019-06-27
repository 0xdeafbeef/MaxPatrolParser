from xlsxwriter.workbook import Workbook
import csv
import os


def save_to_excell(csvfile):
    workbook = Workbook(csvfile[:-4] + '.xlsx', options={'strings_to_urls': False, 'constant_memory': True})
    worksheet = workbook.add_worksheet()
    with open(csvfile, 'rt', encoding='cp1251') as f:
        reader = csv.reader(f)
        for r, row in enumerate(reader):
            for c, col in enumerate(row):
                worksheet.write(r, c, col)
    workbook.close()
    os.remove(csvfile)
