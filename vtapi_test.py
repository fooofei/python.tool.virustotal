# coding=utf-8
from __future__ import unicode_literals
from __future__ import print_function

import sys
import os
import six
from io_in_out import io_hash_stream
from io_in_out import io_print
from io_in_out import io_iter_files_from_arg
from io_in_out import io_hash_fullpath


from vtapi import vt_rescan_from_resource
from vtapi import vt_report_from_resource
from vtapi import vt_batch_sync_report
from vtapi import vt_batch_async_report
from vtapi import vt_check_reports_equal
from vtapi import Report, vt_scan, JsonReport
from vtapi import vt_make_resource_from_hashs
from vtapi import vt_batch_async_rescan
from vtapi import vt_batch_async_scan
from vtapi import _vt_report_resources_to_set
from vtapi import vt_batch_async_report_fullpath, vt_search


# tests
#

def test_report(r):
    if not r.report_ok:
        print(r)
        return

    print_element = (lambda e: print('\t{}'.format(e)))

    print('default_report')
    map(print_element, r.default_report())

    print('first_positive')
    print_element(r.first_positive())

    print('first_reliable_positive')
    print_element(r.first_reliable_positive())

    print('all_report')
    map(print_element, r.all_report())

    print('detect_rate')
    print_element(r.detect_rate())


def test():
    test_data_1 = '''\
        {"scans": {"Bkav": {"detected": true, "version": "1.3.0.8876", "result": "W32.UsbAutoitNHc.Worm", "update": "20170425"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "nProtect": {"detected": false, "version": "2017-04-25.02", "result": null, "update": "20170425"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20170421"}, "CAT-QuickHeal": {"detected": true, "version": "14.00", "result": "Worm.AutoIT.Win32.S", "update": "20170425"}, "McAfee": {"detected": true, "version": "6.0.6.653", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Malwarebytes": {"detected": false, "version": "2.1.1.1115", "result": null, "update": "20170425"}, "Zillya": {"detected": true, "version": "2.0.0.3263", "result": "Worm.AutoIt.Win32.13933", "update": "20170425"}, "AegisLab": {"detected": false, "version": "4.2", "result": null, "update": "20170425"}, "TheHacker": {"detected": false, "version": "6.8.0.5.1468", "result": null, "update": "20170424"}, "K7GW": {"detected": true, "version": "10.9.23121", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "K7AntiVirus": {"detected": true, "version": "10.9.23125", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "Arcabit": {"detected": true, "version": "1.0.0.802", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Baidu": {"detected": false, "version": "1.0.0.2", "result": null, "update": "20170424"}, "F-Prot": {"detected": false, "version": "4.7.1.166", "result": null, "update": "20170425"}, "Symantec": {"detected": true, "version": "1.3.0.0", "result": "Trojan Horse", "update": "20170425"}, "ESET-NOD32": {"detected": true, "version": "15311", "result": "Win32/Autoit.NB", "update": "20170425"}, "TrendMicro-HouseCall": {"detected": true, "version": "9.900.0.1004", "result": "WORM_IPPEDO.B", "update": "20170425"}, "Avast": {"detected": true, "version": "8.0.1489.320", "result": "Other:Malware-gen [Trj]", "update": "20170425"}, "ClamAV": {"detected": false, "version": "0.99.2.0", "result": null, "update": "20170425"}, "Kaspersky": {"detected": true, "version": "15.0.1.13", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "BitDefender": {"detected": true, "version": "7.2", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "SUPERAntiSpyware": {"detected": false, "version": "5.6.0.1032", "result": null, "update": "20170425"}, "Rising": {"detected": true, "version": "28.0.0.1", "result": "Worm.Win32.Autoit.eah (classic) ", "update": "20170425"}, "Ad-Aware": {"detected": true, "version": "3.0.3.1010", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Emsisoft": {"detected": true, "version": "4.0.0.834", "result": "Trojan.Autoit.BQX (B)", "update": "20170425"}, "Comodo": {"detected": true, "version": "26976", "result": "UnclassifiedMalware", "update": "20170425"}, "F-Secure": {"detected": true, "version": "11.0.19100.45", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "DrWeb": {"detected": true, "version": "7.0.28.2020", "result": "Win32.HLLW.Siggen.5580", "update": "20170425"}, "VIPRE": {"detected": true, "version": "57624", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "TrendMicro": {"detected": true, "version": "9.740.0.1012", "result": "WORM_IPPEDO.B", "update": "20170425"}, "McAfee-GW-Edition": {"detected": true, "version": "v2015", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Sophos": {"detected": true, "version": "4.98.0", "result": "W32/Autorun-CEA", "update": "20170425"}, "Cyren": {"detected": false, "version": "5.4.30.7", "result": null, "update": "20170425"}, "Jiangmin": {"detected": false, "version": "16.0.100", "result": null, "update": "20170425"}, "Webroot": {"detected": false, "version": "1.0.0.207", "result": null, "update": "20170426"}, "Avira": {"detected": true, "version": "8.3.3.4", "result": "WORM/Verecno.Gen2", "update": "20170425"}, "Antiy-AVL": {"detected": false, "version": "1.0.0.1", "result": null, "update": "20170425"}, "Kingsoft": {"detected": false, "version": "2013.8.14.323", "result": null, "update": "20170426"}, "Microsoft": {"detected": true, "version": "1.1.13701.0", "result": "Worm:Win32/Autorun.AHV", "update": "20170425"}, "ViRobot": {"detected": true, "version": "2014.3.20.0", "result": "Trojan.Win32.Autoit.136125[h]", "update": "20170425"}, "AhnLab-V3": {"detected": true, "version": "3.9.0.17342", "result": "BinImage/Autoit", "update": "20170425"}, "ZoneAlarm": {"detected": true, "version": "1.0", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "GData": {"detected": true, "version": "A:25.12056B:25.9393", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "TotalDefense": {"detected": false, "version": "37.1.62.1", "result": null, "update": "20170425"}, "VBA32": {"detected": false, "version": "3.12.26.4", "result": null, "update": "20170421"}, "AVware": {"detected": true, "version": "1.5.0.42", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "Zoner": {"detected": false, "version": "1.0", "result": null, "update": "20170425"}, "Tencent": {"detected": true, "version": "1.0.0.1", "result": "Win32.Worm.Autoit.Akfc", "update": "20170426"}, "Yandex": {"detected": true, "version": "5.5.1.3", "result": "Trojan.Agent.Gen.ABP", "update": "20170424"}, "Ikarus": {"detected": true, "version": "0.1.5.2", "result": "Worm.Win32.AutoIt", "update": "20170425"}, "Fortinet": {"detected": false, "version": "5.4.233.0", "result": null, "update": "20170425"}, "AVG": {"detected": true, "version": "16.0.0.4776", "result": "Autoit", "update": "20170425"}, "Panda": {"detected": true, "version": "4.6.4.2", "result": "Trj/Autoit.AF", "update": "20170424"}, "Qihoo-360": {"detected": true, "version": "1.0.0.1120", "result": "virus.au3.heur.b", "update": "20170426"}}, "scan_id": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576-1493195400", "sha1": "a6e25643892232cc04477b1b5f9057255523cd01", "resource": "e58c5e3f461089ca9688d3aca204ea70", "response_code": 1, "scan_date": "2017-04-26 08:30:00", "permalink": "https://www.virustotal.com/file/a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576/analysis/1493195400/", "verbose_msg": "Scan finished, information embedded", "total": 55, "positives": 37, "sha256": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576", "md5": "e58c5e3f461089ca9688d3aca204ea70"}
        '''
    test_data_2 = '''\
    [{"scans": {"Bkav": {"detected": true, "version": "1.3.0.8876", "result": "W32.UsbAutoitNHc.Worm", "update": "20170425"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "nProtect": {"detected": false, "version": "2017-04-25.02", "result": null, "update": "20170425"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20170421"}, "CAT-QuickHeal": {"detected": true, "version": "14.00", "result": "Worm.AutoIT.Win32.S", "update": "20170425"}, "McAfee": {"detected": true, "version": "6.0.6.653", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Malwarebytes": {"detected": false, "version": "2.1.1.1115", "result": null, "update": "20170425"}, "Zillya": {"detected": true, "version": "2.0.0.3263", "result": "Worm.AutoIt.Win32.13933", "update": "20170425"}, "AegisLab": {"detected": false, "version": "4.2", "result": null, "update": "20170425"}, "TheHacker": {"detected": false, "version": "6.8.0.5.1468", "result": null, "update": "20170424"}, "K7GW": {"detected": true, "version": "10.9.23121", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "K7AntiVirus": {"detected": true, "version": "10.9.23125", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "Arcabit": {"detected": true, "version": "1.0.0.802", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Baidu": {"detected": false, "version": "1.0.0.2", "result": null, "update": "20170424"}, "F-Prot": {"detected": false, "version": "4.7.1.166", "result": null, "update": "20170425"}, "Symantec": {"detected": true, "version": "1.3.0.0", "result": "Trojan Horse", "update": "20170425"}, "ESET-NOD32": {"detected": true, "version": "15311", "result": "Win32/Autoit.NB", "update": "20170425"}, "TrendMicro-HouseCall": {"detected": true, "version": "9.900.0.1004", "result": "WORM_IPPEDO.B", "update": "20170425"}, "Avast": {"detected": true, "version": "8.0.1489.320", "result": "Other:Malware-gen [Trj]", "update": "20170425"}, "ClamAV": {"detected": false, "version": "0.99.2.0", "result": null, "update": "20170425"}, "Kaspersky": {"detected": true, "version": "15.0.1.13", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "BitDefender": {"detected": true, "version": "7.2", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "SUPERAntiSpyware": {"detected": false, "version": "5.6.0.1032", "result": null, "update": "20170425"}, "Rising": {"detected": true, "version": "28.0.0.1", "result": "Worm.Win32.Autoit.eah (classic) ", "update": "20170425"}, "Ad-Aware": {"detected": true, "version": "3.0.3.1010", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Emsisoft": {"detected": true, "version": "4.0.0.834", "result": "Trojan.Autoit.BQX (B)", "update": "20170425"}, "Comodo": {"detected": true, "version": "26976", "result": "UnclassifiedMalware", "update": "20170425"}, "F-Secure": {"detected": true, "version": "11.0.19100.45", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "DrWeb": {"detected": true, "version": "7.0.28.2020", "result": "Win32.HLLW.Siggen.5580", "update": "20170425"}, "VIPRE": {"detected": true, "version": "57624", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "TrendMicro": {"detected": true, "version": "9.740.0.1012", "result": "WORM_IPPEDO.B", "update": "20170425"}, "McAfee-GW-Edition": {"detected": true, "version": "v2015", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Sophos": {"detected": true, "version": "4.98.0", "result": "W32/Autorun-CEA", "update": "20170425"}, "Cyren": {"detected": false, "version": "5.4.30.7", "result": null, "update": "20170425"}, "Jiangmin": {"detected": false, "version": "16.0.100", "result": null, "update": "20170425"}, "Webroot": {"detected": false, "version": "1.0.0.207", "result": null, "update": "20170426"}, "Avira": {"detected": true, "version": "8.3.3.4", "result": "WORM/Verecno.Gen2", "update": "20170425"}, "Antiy-AVL": {"detected": false, "version": "1.0.0.1", "result": null, "update": "20170425"}, "Kingsoft": {"detected": false, "version": "2013.8.14.323", "result": null, "update": "20170426"}, "Microsoft": {"detected": true, "version": "1.1.13701.0", "result": "Worm:Win32/Autorun.AHV", "update": "20170425"}, "ViRobot": {"detected": true, "version": "2014.3.20.0", "result": "Trojan.Win32.Autoit.136125[h]", "update": "20170425"}, "AhnLab-V3": {"detected": true, "version": "3.9.0.17342", "result": "BinImage/Autoit", "update": "20170425"}, "ZoneAlarm": {"detected": true, "version": "1.0", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "GData": {"detected": true, "version": "A:25.12056B:25.9393", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "TotalDefense": {"detected": false, "version": "37.1.62.1", "result": null, "update": "20170425"}, "VBA32": {"detected": false, "version": "3.12.26.4", "result": null, "update": "20170421"}, "AVware": {"detected": true, "version": "1.5.0.42", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "Zoner": {"detected": false, "version": "1.0", "result": null, "update": "20170425"}, "Tencent": {"detected": true, "version": "1.0.0.1", "result": "Win32.Worm.Autoit.Akfc", "update": "20170426"}, "Yandex": {"detected": true, "version": "5.5.1.3", "result": "Trojan.Agent.Gen.ABP", "update": "20170424"}, "Ikarus": {"detected": true, "version": "0.1.5.2", "result": "Worm.Win32.AutoIt", "update": "20170425"}, "Fortinet": {"detected": false, "version": "5.4.233.0", "result": null, "update": "20170425"}, "AVG": {"detected": true, "version": "16.0.0.4776", "result": "Autoit", "update": "20170425"}, "Panda": {"detected": true, "version": "4.6.4.2", "result": "Trj/Autoit.AF", "update": "20170424"}, "Qihoo-360": {"detected": true, "version": "1.0.0.1120", "result": "virus.au3.heur.b", "update": "20170426"}}, "scan_id": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576-1493195400", "sha1": "a6e25643892232cc04477b1b5f9057255523cd01", "resource": "e58c5e3f461089ca9688d3aca204ea70", "response_code": 1, "scan_date": "2017-04-26 08:30:00", "permalink": "https://www.virustotal.com/file/a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576/analysis/1493195400/", "verbose_msg": "Scan finished, information embedded", "total": 55, "positives": 37, "sha256": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576", "md5": "e58c5e3f461089ca9688d3aca204ea70"}, {"scans": {"Bkav": {"detected": false, "version": "1.3.0.4959", "result": null, "update": "20140405"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Trojan.Batbvg.A", "update": "20140405"}, "nProtect": {"detected": true, "version": "2014-04-04.01", "result": "Trojan.Batbvg.A", "update": "20140404"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20140404"}, "CAT-QuickHeal": {"detected": true, "version": "12.00", "result": "BAT.BVGen", "update": "20140405"}, "McAfee": {"detected": true, "version": "6.0.4.564", "result": "Bat/bvg.kit", "update": "20140405"}, "Malwarebytes": {"detected": false, "version": "1.75.0001", "result": null, "update": "20140405"}, "AegisLab": {"detected": false, "version": "1.5", "result": null, "update": "20140405"}, "TheHacker": {"detected": false, "version": null, "result": null, "update": "20140404"}, "K7GW": {"detected": true, "version": "9.176.11663", "result": "Exploit ( 04c559641 )", "update": "20140404"}, "K7AntiVirus": {"detected": true, "version": "9.176.11663", "result": "Virus ( a1ee0c420 )", "update": "20140404"}, "NANO-Antivirus": {"detected": true, "version": "0.28.0.58873", "result": "Riskware.Script.BVGen.fzjs", "update": "20140405"}, "F-Prot": {"detected": true, "version": "4.7.1.166", "result": "BAT/BVGN.B", "update": "20140405"}, "Symantec": {"detected": true, "version": "20131.1.5.61", "result": "Trojan.ConstructKit", "update": "20140405"}, "Norman": {"detected": false, "version": "7.03.02", "result": null, "update": "20140404"}, "TotalDefense": {"detected": true, "version": "37.0.10859", "result": "BAT/BVGen!kit", "update": "20140405"}, "TrendMicro-HouseCall": {"detected": true, "version": "9.700-1001", "result": "TROJ_CONSTRUC.A", "update": "20140405"}, "Avast": {"detected": true, "version": "8.0.1489.320", "result": "BV:Agent-US [Trj]", "update": "20140405"}, "ClamAV": {"detected": true, "version": "0.97.3", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "Kaspersky": {"detected": true, "version": "12.0.0.1225", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "BitDefender": {"detected": true, "version": "7.2", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Agnitum": {"detected": true, "version": "5.5.1.3", "result": "BAT.BVG.Kit", "update": "20140404"}, "ViRobot": {"detected": false, "version": "2011.4.7.4223", "result": null, "update": "20140405"}, "ByteHero": {"detected": false, "version": "1.0.0.1", "result": null, "update": "20140405"}, "Ad-Aware": {"detected": true, "version": "12.0.163.0", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Emsisoft": {"detected": true, "version": "3.0.0.596", "result": "Trojan.Batbvg.A (B)", "update": "20140405"}, "Comodo": {"detected": false, "version": "18052", "result": null, "update": "20140405"}, "F-Secure": {"detected": true, "version": "11.0.19100.45", "result": "Trojan.Batbvg.A", "update": "20140405"}, "DrWeb": {"detected": true, "version": "7.00.8.02260", "result": "BATCH.Virus", "update": "20140405"}, "VIPRE": {"detected": false, "version": "28044", "result": null, "update": "20140405"}, "AntiVir": {"detected": true, "version": "7.11.141.94", "result": "KIT/BAT.BVGHH.11", "update": "20140405"}, "TrendMicro": {"detected": true, "version": "9.740-1012", "result": "TROJ_CONSTRUC.A", "update": "20140405"}, "McAfee-GW-Edition": {"detected": true, "version": "2013", "result": "Bat/bvg.kit", "update": "20140405"}, "Sophos": {"detected": true, "version": "4.98.0", "result": "Troj/Batbvg-A", "update": "20140405"}, "Jiangmin": {"detected": false, "version": "16.0.100", "result": null, "update": "20140405"}, "Antiy-AVL": {"detected": true, "version": "0.1.0.1", "result": "HackTool[Constructor]/BAT.BVGHH", "update": "20140405"}, "Kingsoft": {"detected": false, "version": "2013.04.09.267", "result": null, "update": "20140405"}, "Microsoft": {"detected": false, "version": "1.10401", "result": null, "update": "20140405"}, "SUPERAntiSpyware": {"detected": false, "version": "5.6.0.1032", "result": null, "update": "20140405"}, "GData": {"detected": true, "version": "24", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Commtouch": {"detected": true, "version": "5.4.1.7", "result": "BAT/BVGN.B", "update": "20140405"}, "AhnLab-V3": {"detected": true, "version": "None", "result": "Constructor/Bvghh", "update": "20140405"}, "VBA32": {"detected": true, "version": "3.12.26.0", "result": "Constructor.BAT.BVGHH.11", "update": "20140404"}, "Panda": {"detected": true, "version": "10.0.3.5", "result": "Constructor/BVgen.A", "update": "20140405"}, "ESET-NOD32": {"detected": false, "version": "9639", "result": null, "update": "20140405"}, "Rising": {"detected": true, "version": "25.0.0.11", "result": "BAT:Constructor.BAT.BVGen!34788", "update": "20140405"}, "Ikarus": {"detected": true, "version": "T3.1.5.6.0", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "Fortinet": {"detected": false, "version": "4", "result": null, "update": "20140404"}, "AVG": {"detected": false, "version": "13.0.0.3169", "result": null, "update": "20140405"}, "Baidu-International": {"detected": false, "version": "3.5.1.41473", "result": null, "update": "20140405"}, "Qihoo-360": {"detected": false, "version": "1.0.0.1015", "result": null, "update": "20140405"}}, "scan_id": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c-1396699898", "sha1": "ab385a9c88e894ccf63c92e19aedbefdbbdfed2a", "resource": "3fdb88cb17f320b55a372ecf09e3e4c5", "response_code": 1, "scan_date": "2014-04-05 12:11:38", "permalink": "https://www.virustotal.com/file/76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c/analysis/1396699898/", "verbose_msg": "Scan finished, information embedded", "total": 51, "positives": 32, "sha256": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c", "md5": "3fdb88cb17f320b55a372ecf09e3e4c5"}]
    '''
    r = Report(test_data_1)
    # test_report(r)

    rs = Report.dispatch_report(test_data_2)
    map(test_report, rs)


def make_random_file_content():
    import random
    from StringIO import StringIO

    f = StringIO()
    for i in range(0, 10000):
        f.write(random.randint(0, 10000))
    return f.getvalue()


def make_random_file_vt_not_exists():
    from StringIO import StringIO
    while True:
        fc = make_random_file_content()
        fc_md5 = io_hash_stream(StringIO(fc), 'md5')
        # test if exists
        r = vt_report_from_resource(fc_md5)
        if r and not Report(r).ok:
            break

    return {'file_content': fc, 'md5': fc_md5}


def unit_test_scan():
    v = make_random_file_vt_not_exists()
    print('\tmake random file {}'.format(v['md5']))
    r = vt_scan(file_content=v['file_content'], file_name='360_qex_random_test')
    print(JsonReport(r))
    print('pass {}'.format(unit_test_scan.__name__))


def unit_test_vt_make_resource_from_hashs():
    valid_md5 = 'b0f6d5758c76762233c29b74094cecd7'
    valid_sha1 = 'de88b56e8aaa91772e5b2768fe0d240a02b1b390'
    valid_sha256 = 'ad086bcfc8f11d9813626d379cc04342921e5d1453925c69f76b30cdc13a566c'
    invalid_hash1 = '23423'
    invalid_hash2 = 'okjoljoijoasf'

    valid_hashs = [valid_md5, valid_sha1, valid_sha256]
    assert (','.join(valid_hashs) == vt_make_resource_from_hashs(valid_hashs))
    assert (','.join(valid_hashs) == vt_make_resource_from_hashs(valid_hashs + [invalid_hash1]))
    assert (','.join(valid_hashs) == vt_make_resource_from_hashs(valid_hashs + [invalid_hash2]))
    assert (','.join(valid_hashs) == vt_make_resource_from_hashs(valid_hashs + [invalid_hash1, invalid_hash2]))
    assert (vt_make_resource_from_hashs([invalid_hash1, invalid_hash2]) == u'')

    print('pass {}'.format(unit_test_vt_make_resource_from_hashs.__name__))


def unit_test_batch_report_and_rescan(is_test_report=True, is_test_rescan=True):
    # 这里面有 vt 存在的 和不存在的
    resources = ["003204036798a24f6f9941c08b3ed9e4", "00790a4633d2c0f89143bbdba4518bfa",
                 "0172de403f750a5093e5cf2744c72cda", "02da91934abee49b14e49463ca31454e",
                 "0482ee1c7011e1957f51155840ebc61e", "066339aac96d09af1eda2c7c4e007665",
                 "06cdf67180c30c4dcba79b94a534144b", "087f24d01b9a4592fed102ce469894e8",
                 "0a6c44098a770c9d337aeba5389101c7", "0dae3efec1ff23d53f145b4839de9360",
                 "0ea4b7cdb5289649df07139f1b789e96", "0ec9bbfc2ae5963cfc60c3e45d093db7",
                 "11654bb5364018e66db1997c63a9f128", "118192adbf094d937bfab60680e4c7fe",
                 "141f908bce4dfdb78013a32a7b591075", "19f736c757ef381f1f70b95dbb5fa8a1",
                 "1b50a1e3c58f101b75e3bc86c92f7c61", "1be00f42fcd4a3329859e751b1e04c16",
                 "1d58949a861d76ccc88a069ef523fbe3", "1efc6f2c9074070b6b17d90a2e81549d",
                 "204da224421af00e1c0bb52aeded4afa", "223b11459799185475f6018531c3545d",
                 "2257f3dc9221066754cbbc94c2e12da0", "22e34585209337f6a4e4ea4e2fdbab43",
                 "23f4795ac4853f23c5e64a1f77aeb335", "2539a91262775db1afd0ee28a345c45d",
                 "2699481fab0ded9319da877b038aa5ae", "0c48f59dc2b9b7dfb4eb2afef70dc52c",
                 "1e0b1ac398b8a8a49c7efa55ea4ee96d", "29e07d7425a54d07f1701b01aa2557ed"]

    resources = set(resources)
    print('\tresource len {}'.format(len(resources)))

    if is_test_report:
        reports = vt_batch_sync_report(resources)

        import time
        t = time.clock()
        r1 = vt_batch_async_report(resources)

        print('\tasync {} reports len = {}'.format(
            time.clock() - t,
            len(reports)))

        vt_check_reports_equal(r_new=r1, r_old=reports)

        t = time.clock()
        r2 = vt_batch_sync_report(resources)
        print('\tsync {} reports len = {}'.format(
            time.clock() - t,
            len(reports)))
        vt_check_reports_equal(r_new=r2, r_old=reports)

    if is_test_rescan:
        reports = vt_batch_async_rescan(resources)
        assert (len(resources) == len(reports))

    print('pass {}'.format(unit_test_batch_report_and_rescan.__name__))


def unit_test_vt_report_to_set():
    test_data_2 = '''\
[{"scans": {"Bkav": {"detected": true, "version": "1.3.0.8876", "result": "W32.UsbAutoitNHc.Worm", "update": "20170425"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "nProtect": {"detected": false, "version": "2017-04-25.02", "result": null, "update": "20170425"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20170421"}, "CAT-QuickHeal": {"detected": true, "version": "14.00", "result": "Worm.AutoIT.Win32.S", "update": "20170425"}, "McAfee": {"detected": true, "version": "6.0.6.653", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Malwarebytes": {"detected": false, "version": "2.1.1.1115", "result": null, "update": "20170425"}, "Zillya": {"detected": true, "version": "2.0.0.3263", "result": "Worm.AutoIt.Win32.13933", "update": "20170425"}, "AegisLab": {"detected": false, "version": "4.2", "result": null, "update": "20170425"}, "TheHacker": {"detected": false, "version": "6.8.0.5.1468", "result": null, "update": "20170424"}, "K7GW": {"detected": true, "version": "10.9.23121", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "K7AntiVirus": {"detected": true, "version": "10.9.23125", "result": "Trojan ( 00499ac61 )", "update": "20170425"}, "Arcabit": {"detected": true, "version": "1.0.0.802", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Baidu": {"detected": false, "version": "1.0.0.2", "result": null, "update": "20170424"}, "F-Prot": {"detected": false, "version": "4.7.1.166", "result": null, "update": "20170425"}, "Symantec": {"detected": true, "version": "1.3.0.0", "result": "Trojan Horse", "update": "20170425"}, "ESET-NOD32": {"detected": true, "version": "15311", "result": "Win32/Autoit.NB", "update": "20170425"}, "TrendMicro-HouseCall": {"detected": true, "version": "9.900.0.1004", "result": "WORM_IPPEDO.B", "update": "20170425"}, "Avast": {"detected": true, "version": "8.0.1489.320", "result": "Other:Malware-gen [Trj]", "update": "20170425"}, "ClamAV": {"detected": false, "version": "0.99.2.0", "result": null, "update": "20170425"}, "Kaspersky": {"detected": true, "version": "15.0.1.13", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "BitDefender": {"detected": true, "version": "7.2", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "SUPERAntiSpyware": {"detected": false, "version": "5.6.0.1032", "result": null, "update": "20170425"}, "Rising": {"detected": true, "version": "28.0.0.1", "result": "Worm.Win32.Autoit.eah (classic) ", "update": "20170425"}, "Ad-Aware": {"detected": true, "version": "3.0.3.1010", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "Emsisoft": {"detected": true, "version": "4.0.0.834", "result": "Trojan.Autoit.BQX (B)", "update": "20170425"}, "Comodo": {"detected": true, "version": "26976", "result": "UnclassifiedMalware", "update": "20170425"}, "F-Secure": {"detected": true, "version": "11.0.19100.45", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "DrWeb": {"detected": true, "version": "7.0.28.2020", "result": "Win32.HLLW.Siggen.5580", "update": "20170425"}, "VIPRE": {"detected": true, "version": "57624", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "TrendMicro": {"detected": true, "version": "9.740.0.1012", "result": "WORM_IPPEDO.B", "update": "20170425"}, "McAfee-GW-Edition": {"detected": true, "version": "v2015", "result": "W32/Autorun.worm.aapp", "update": "20170425"}, "Sophos": {"detected": true, "version": "4.98.0", "result": "W32/Autorun-CEA", "update": "20170425"}, "Cyren": {"detected": false, "version": "5.4.30.7", "result": null, "update": "20170425"}, "Jiangmin": {"detected": false, "version": "16.0.100", "result": null, "update": "20170425"}, "Webroot": {"detected": false, "version": "1.0.0.207", "result": null, "update": "20170426"}, "Avira": {"detected": true, "version": "8.3.3.4", "result": "WORM/Verecno.Gen2", "update": "20170425"}, "Antiy-AVL": {"detected": false, "version": "1.0.0.1", "result": null, "update": "20170425"}, "Kingsoft": {"detected": false, "version": "2013.8.14.323", "result": null, "update": "20170426"}, "Microsoft": {"detected": true, "version": "1.1.13701.0", "result": "Worm:Win32/Autorun.AHV", "update": "20170425"}, "ViRobot": {"detected": true, "version": "2014.3.20.0", "result": "Trojan.Win32.Autoit.136125[h]", "update": "20170425"}, "AhnLab-V3": {"detected": true, "version": "3.9.0.17342", "result": "BinImage/Autoit", "update": "20170425"}, "ZoneAlarm": {"detected": true, "version": "1.0", "result": "Worm.Win32.AutoIt.aiy", "update": "20170425"}, "GData": {"detected": true, "version": "A:25.12056B:25.9393", "result": "Trojan.Autoit.BQX", "update": "20170425"}, "TotalDefense": {"detected": false, "version": "37.1.62.1", "result": null, "update": "20170425"}, "VBA32": {"detected": false, "version": "3.12.26.4", "result": null, "update": "20170421"}, "AVware": {"detected": true, "version": "1.5.0.42", "result": "Worm.Win32.AutoIt.aiy (v)", "update": "20170425"}, "Zoner": {"detected": false, "version": "1.0", "result": null, "update": "20170425"}, "Tencent": {"detected": true, "version": "1.0.0.1", "result": "Win32.Worm.Autoit.Akfc", "update": "20170426"}, "Yandex": {"detected": true, "version": "5.5.1.3", "result": "Trojan.Agent.Gen.ABP", "update": "20170424"}, "Ikarus": {"detected": true, "version": "0.1.5.2", "result": "Worm.Win32.AutoIt", "update": "20170425"}, "Fortinet": {"detected": false, "version": "5.4.233.0", "result": null, "update": "20170425"}, "AVG": {"detected": true, "version": "16.0.0.4776", "result": "Autoit", "update": "20170425"}, "Panda": {"detected": true, "version": "4.6.4.2", "result": "Trj/Autoit.AF", "update": "20170424"}, "Qihoo-360": {"detected": true, "version": "1.0.0.1120", "result": "virus.au3.heur.b", "update": "20170426"}}, "scan_id": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576-1493195400", "sha1": "a6e25643892232cc04477b1b5f9057255523cd01", "resource": "e58c5e3f461089ca9688d3aca204ea70", "response_code": 1, "scan_date": "2017-04-26 08:30:00", "permalink": "https://www.virustotal.com/file/a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576/analysis/1493195400/", "verbose_msg": "Scan finished, information embedded", "total": 55, "positives": 37, "sha256": "a388a6cbbec942b0a772d7d1e0a3c0f3b9adf93dd56ddb9f60b0b30d27915576", "md5": "e58c5e3f461089ca9688d3aca204ea70"}, {"scans": {"Bkav": {"detected": false, "version": "1.3.0.4959", "result": null, "update": "20140405"}, "MicroWorld-eScan": {"detected": true, "version": "12.0.250.0", "result": "Trojan.Batbvg.A", "update": "20140405"}, "nProtect": {"detected": true, "version": "2014-04-04.01", "result": "Trojan.Batbvg.A", "update": "20140404"}, "CMC": {"detected": false, "version": "1.1.0.977", "result": null, "update": "20140404"}, "CAT-QuickHeal": {"detected": true, "version": "12.00", "result": "BAT.BVGen", "update": "20140405"}, "McAfee": {"detected": true, "version": "6.0.4.564", "result": "Bat/bvg.kit", "update": "20140405"}, "Malwarebytes": {"detected": false, "version": "1.75.0001", "result": null, "update": "20140405"}, "AegisLab": {"detected": false, "version": "1.5", "result": null, "update": "20140405"}, "TheHacker": {"detected": false, "version": null, "result": null, "update": "20140404"}, "K7GW": {"detected": true, "version": "9.176.11663", "result": "Exploit ( 04c559641 )", "update": "20140404"}, "K7AntiVirus": {"detected": true, "version": "9.176.11663", "result": "Virus ( a1ee0c420 )", "update": "20140404"}, "NANO-Antivirus": {"detected": true, "version": "0.28.0.58873", "result": "Riskware.Script.BVGen.fzjs", "update": "20140405"}, "F-Prot": {"detected": true, "version": "4.7.1.166", "result": "BAT/BVGN.B", "update": "20140405"}, "Symantec": {"detected": true, "version": "20131.1.5.61", "result": "Trojan.ConstructKit", "update": "20140405"}, "Norman": {"detected": false, "version": "7.03.02", "result": null, "update": "20140404"}, "TotalDefense": {"detected": true, "version": "37.0.10859", "result": "BAT/BVGen!kit", "update": "20140405"}, "TrendMicro-HouseCall": {"detected": true, "version": "9.700-1001", "result": "TROJ_CONSTRUC.A", "update": "20140405"}, "Avast": {"detected": true, "version": "8.0.1489.320", "result": "BV:Agent-US [Trj]", "update": "20140405"}, "ClamAV": {"detected": true, "version": "0.97.3", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "Kaspersky": {"detected": true, "version": "12.0.0.1225", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "BitDefender": {"detected": true, "version": "7.2", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Agnitum": {"detected": true, "version": "5.5.1.3", "result": "BAT.BVG.Kit", "update": "20140404"}, "ViRobot": {"detected": false, "version": "2011.4.7.4223", "result": null, "update": "20140405"}, "ByteHero": {"detected": false, "version": "1.0.0.1", "result": null, "update": "20140405"}, "Ad-Aware": {"detected": true, "version": "12.0.163.0", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Emsisoft": {"detected": true, "version": "3.0.0.596", "result": "Trojan.Batbvg.A (B)", "update": "20140405"}, "Comodo": {"detected": false, "version": "18052", "result": null, "update": "20140405"}, "F-Secure": {"detected": true, "version": "11.0.19100.45", "result": "Trojan.Batbvg.A", "update": "20140405"}, "DrWeb": {"detected": true, "version": "7.00.8.02260", "result": "BATCH.Virus", "update": "20140405"}, "VIPRE": {"detected": false, "version": "28044", "result": null, "update": "20140405"}, "AntiVir": {"detected": true, "version": "7.11.141.94", "result": "KIT/BAT.BVGHH.11", "update": "20140405"}, "TrendMicro": {"detected": true, "version": "9.740-1012", "result": "TROJ_CONSTRUC.A", "update": "20140405"}, "McAfee-GW-Edition": {"detected": true, "version": "2013", "result": "Bat/bvg.kit", "update": "20140405"}, "Sophos": {"detected": true, "version": "4.98.0", "result": "Troj/Batbvg-A", "update": "20140405"}, "Jiangmin": {"detected": false, "version": "16.0.100", "result": null, "update": "20140405"}, "Antiy-AVL": {"detected": true, "version": "0.1.0.1", "result": "HackTool[Constructor]/BAT.BVGHH", "update": "20140405"}, "Kingsoft": {"detected": false, "version": "2013.04.09.267", "result": null, "update": "20140405"}, "Microsoft": {"detected": false, "version": "1.10401", "result": null, "update": "20140405"}, "SUPERAntiSpyware": {"detected": false, "version": "5.6.0.1032", "result": null, "update": "20140405"}, "GData": {"detected": true, "version": "24", "result": "Trojan.Batbvg.A", "update": "20140405"}, "Commtouch": {"detected": true, "version": "5.4.1.7", "result": "BAT/BVGN.B", "update": "20140405"}, "AhnLab-V3": {"detected": true, "version": "None", "result": "Constructor/Bvghh", "update": "20140405"}, "VBA32": {"detected": true, "version": "3.12.26.0", "result": "Constructor.BAT.BVGHH.11", "update": "20140404"}, "Panda": {"detected": true, "version": "10.0.3.5", "result": "Constructor/BVgen.A", "update": "20140405"}, "ESET-NOD32": {"detected": false, "version": "9639", "result": null, "update": "20140405"}, "Rising": {"detected": true, "version": "25.0.0.11", "result": "BAT:Constructor.BAT.BVGen!34788", "update": "20140405"}, "Ikarus": {"detected": true, "version": "T3.1.5.6.0", "result": "Constructor.BAT.BVGHH.11", "update": "20140405"}, "Fortinet": {"detected": false, "version": "4", "result": null, "update": "20140404"}, "AVG": {"detected": false, "version": "13.0.0.3169", "result": null, "update": "20140405"}, "Baidu-International": {"detected": false, "version": "3.5.1.41473", "result": null, "update": "20140405"}, "Qihoo-360": {"detected": false, "version": "1.0.0.1015", "result": null, "update": "20140405"}}, "scan_id": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c-1396699898", "sha1": "ab385a9c88e894ccf63c92e19aedbefdbbdfed2a", "resource": "3fdb88cb17f320b55a372ecf09e3e4c5", "response_code": 1, "scan_date": "2014-04-05 12:11:38", "permalink": "https://www.virustotal.com/file/76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c/analysis/1396699898/", "verbose_msg": "Scan finished, information embedded", "total": 51, "positives": 32, "sha256": "76e02fa84b32a0ebf24b558ae358d7e80c828584d90342120bc45df2d41ce47c", "md5": "3fdb88cb17f320b55a372ecf09e3e4c5"}]
'''
    rs = Report.dispatch_report(test_data_2)
    r = _vt_report_resources_to_set(rs)
    assert (r == set([u'3fdb88cb17f320b55a372ecf09e3e4c5', u'e58c5e3f461089ca9688d3aca204ea70']))
    print('pass {}'.format(unit_test_vt_report_to_set.__name__))


def unit_test_vt_batch_scan():
    import time

    random_files = []

    for _ in range(0, 10):
        random_files.append(make_random_file_vt_not_exists())

    io_print(u'\tok make random file count:{}'.format(len(random_files)))
    reports = vt_batch_async_scan(random_files)

    io_print(u'\tok put vt scan count:{}'.format(len(reports)))

    md5s = [e['md5'] for e in random_files]

    start_time = time.clock()

    io_print(u'\tget reporting until no file is analyzing')

    r = vt_batch_async_report(md5s, if_analyzing_wait=True)

    io_print(u'\tok get report count:{}'.format(len(r)))

    for e in r:
        # print('\t{} {}'.format(e['md5'], e.state))
        print('\t{}'.format(e.simple_report()))
    print('pass {} scan all file cost {}'.format(unit_test_vt_batch_scan.__name__, time.clock() - start_time))


def test_vt_batch_async_report_fullpath():
    fs = io_iter_files_from_arg(sys.argv[1::])

    datas = [{'fullpath': e, 'md5': io_hash_fullpath(e, 'md5')} for e in fs]

    vt_batch_async_report_fullpath(datas, force_rescan=False, upload_vt_not_exists=True)

    for e in datas:
        io_print(e['report'].simple_report())

def test_vt_batch_scan():
    resource_not_exists = 'b0f6d5758c76762233c29b74094cecd7'
    resource_report = '3fdb88cb17f320b55a372ecf09e3e4c5'
    resource_reports = [resource_report, '234234']
    r = vt_report_from_resource('3fdb88cb17f320b55a372ecf09e3e4c5,1111')

def test_vt_search():
    search = u'HEUR.VBA. positives:3- ls:2017-04-22+'

    ss = []
    for result in vt_search(search_modifier=search):
        sys.stdout.write(u'fetch {} '.format(len(result)))
        ss.extend(result)
        if len(ss) > 20:
            break

    print (u'total {}'.format(len(ss)))

def unit_test():
    resource_not_exists = 'b0f6d5758c76762233c29b74094cecd7'
    resource_report = '3fdb88cb17f320b55a372ecf09e3e4c5'
    r = vt_report_from_resource(resource_report)
    print(r)
    print('')
    r = vt_report_from_resource(resource_not_exists)
    print(r)
    print('')
    r = vt_rescan_from_resource(resource_report)
    print(r)
    print('')
    r = vt_rescan_from_resource(resource_not_exists)
    print(r)
    print('')
    unit_test_scan()
    unit_test_vt_make_resource_from_hashs()
    unit_test_batch_report_and_rescan()
    unit_test_vt_report_to_set()
    unit_test_vt_batch_scan()
    test_vt_search()

#
#
#



if __name__ == '__main__':
    # test_vt_batch_async_report_fullpath()
    unit_test()
