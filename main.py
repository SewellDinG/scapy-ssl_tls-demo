#!/usr/bin/env python
# -*- coding: utf-8 -*-

__Author__ = "SewellDinG"

"""
Step 1
+--------------+      +-----------------+
| pcapSplitter +----->+ Session trafiic |
+--------------+      +-----------------+
Step 2
+----------+     +-----------------+     +-------------+     +---------------+
| Category +---->+ Session traffic +---->+ get Feature +---->+ TLSPcapDecode |
+----------+     +-------^---------+     +-------------+     +-------+-------+
                         |                                           |
                         |                                           v
                         |                                       +---+-----+
                         |                   +-----+             | Ether   |
                         +-------------------+ CSV <-------------+ IP      |
                                             +-----+             | TCP     |
                                                                 | SSL/TLS |
                                                                 +---------+
"""
import gettls
from scapy.all import *
import os
import csv


def main():
    root_path = "/Users/go0s/Downloads/py_scapy_cs/session_pcap/"
    # 遍历所有类别下的所有session
    for pcap_name in os.listdir(root_path):
        pcap_path = root_path + pcap_name + "/"
        for pcap_session_name in os.listdir(pcap_path):
            try:
                pcap_session_path = pcap_path + pcap_session_name
                # 初始化TLSPcapDecode类
                TLSPD = gettls.TLSPcapDecode()
                # scapy读取session pcap
                session_pcap = rdpcap(pcap_session_path)
                session_statistic_features = gettls.get_session_statistic_feature(
                    session_pcap, TLSPD)
                # 添加家族label
                session_statistic_features.insert(1, pcap_name)
                # 以csv格式输出
                label_name = pcap_name + ".csv"
                with open(label_name, 'a', encoding='utf8', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    # 仅提取包含SSL/TLS的session pcap info
                    if session_statistic_features[-1] != 0:
                        print(session_statistic_features)
                        writer.writerow(session_statistic_features)
            # 未异常处理，万恶之源，罪过罪过...
            except:
                pass


if __name__ == '__main__':
    main()
