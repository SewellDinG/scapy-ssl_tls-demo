#!/usr/bin/env python
# -*- coding: utf-8 -*-

__Author__ = "SewellDing"

'''
scapy debug demo
e.g
{'si_sport_di_dport': '192.168.1.123:49158-198.100.127.43:443', 'pkts_cnt': 22, 'sessn_dur': 1.041785, 'total_bytes': 6100, 'pkts_len_avg': 321.05263157894734, 'total_bytes_tls': 66878, 'tlss_len_avg': 6687.8, 'tls_cip': 49191, 'tls_comp': 0, 'tls_extlen': 8, 'tls_exttype': 11}
'''

from scapy.all import *
from datetime import datetime
import json


class TLSPcapDecode:
    data = dict()

    def __init__(self):
        # ETHER:读取以太网层协议配置文件
        with open('./protocol/ETHER', 'r', encoding='UTF-8') as f:
            ethers = f.readlines()
        self.ETHER_DICT = dict()
        for ether in ethers:
            ether = ether.strip().strip('\n').strip('\r').strip('\r\n')
            self.ETHER_DICT[int(ether.split(':')[0])] = ether.split(':')[1]

        # IP:读取IP层协议配置文件
        with open('./protocol/IP', 'r', encoding='UTF-8') as f:
            ips = f.readlines()
        self.IP_DICT = dict()
        for ip in ips:
            ip = ip.strip().strip('\n').strip('\r').strip('\r\n')
            self.IP_DICT[int(ip.split(':')[0])] = ip.split(':')[1]

        # PORT:读取应用层协议端口配置文件
        with open('./protocol/PORT', 'r', encoding='UTF-8') as f:
            ports = f.readlines()
        self.PORT_DICT = dict()
        for port in ports:
            port = port.strip().strip('\n').strip('\r').strip('\r\n')
            self.PORT_DICT[int(port.split(':')[0])] = port.split(':')[1]

        # TCP:读取TCP层协议配置文件
        with open('./protocol/TCP', 'r', encoding='UTF-8') as f:
            tcps = f.readlines()
        self.TCP_DICT = dict()
        for tcp in tcps:
            tcp = tcp.strip().strip('\n').strip('\r').strip('\r\n')
            self.TCP_DICT[int(tcp.split(':')[0])] = tcp.split(':')[1]

    # 解析以太网层协议
    def ether_decode(self, p):
        ether_data = dict()
        if p.haslayer("Ether"):
            # p.time -> 毫秒时间戳
            ether_data['time'] = datetime.fromtimestamp(float(p.time)).strftime('%Y-%m-%d %H:%M:%S.%f')
            ether_data['len'] = len(corrupt_bytes(p))
            # ether_data['info'] = p.summary()
            if p.haslayer("IP"):
                ether_data['IP'] = self.ip_decode(p)
            # 赋给类公有变量
            self.data.update(ether_data)
            return self.data
        else:
            ether_data['ether_error'] = False
            self.data.update(ether_data)
            return self.data

    # 解析IP层协议
    def ip_decode(self, p):
        ip_data = dict()
        if p.haslayer("IP"):
            ip = p.getlayer("IP")
            ip_data['source'] = ip.src + ":" + str(ip.sport)
            ip_data['destination'] = ip.dst + ":" + str(ip.dport)
            if p.haslayer("TCP"):
                ip_data['TCP'] = self.tcp_decode(p, ip)
                return ip_data
        elif p.haslayer("IPv6"):
            ipv6 = p.getlayer("IPv6")
            # 未处理
            if p.haslayer("TCP"):
                ip_data = self.tcp_decode(p, ipv6)
                return ip_data
        else:
            ip_data['ip_error'] = False
            return ip_data

    # 解析TCP层协议
    def tcp_decode(self, p, ip):
        tcp_data = dict()
        if p.haslayer("TCP"):
            tcp = p.getlayer("TCP")
            if tcp.dport in self.PORT_DICT:
                tcp_data['Procotol'] = self.PORT_DICT[tcp.dport]
            elif tcp.sport in self.PORT_DICT:
                tcp_data['Procotol'] = self.PORT_DICT[tcp.sport]
            elif tcp.dport in self.TCP_DICT:
                tcp_data['Procotol'] = self.TCP_DICT[tcp.dport]
            elif tcp.sport in self.TCP_DICT:
                tcp_data['Procotol'] = self.TCP_DICT[tcp.sport]
            else:
                tcp_data['Procotol'] = "TCP"
            # tcp.show()
            # 此处非TLS，而是SSL/TLS
            if p.haslayer("SSL/TLS"):
                tcp_data['TLS'] = self.tls_decode(p, ip, tcp)
                return tcp_data
            else:
                return tcp_data
        else:
            tcp_data['tcp_error'] = False
            return tcp_data

    # 解析TLS协议
    def tls_decode(self, p, ip, tcp):
        tls_data = dict()
        if p.haslayer("SSL/TLS"):
            tls = p.getlayer("SSL/TLS")
            time.sleep(1)
            # ls(tls)
            # tls.show()
            # tls version TLS 1.2 0x0303 -> 771
            tls_data['tls_vers'] = tls['TLS Record'].version
            # get tls length
            tls_data['tls_len'] = tls['TLS Record'].length
            # get tls duration
            # get ssl/tls stage 2 info
            try:
                tls['TLS Handshake']
            except IndexError:
                tls_data['tls_step'] = -1
            else:
                tls_data['tls_step'] = tls['TLS Handshake'].type
                # stage 2: Server Hello
                if tls_data['tls_step'] == 2:
                    # tls cipher ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xc027 -> 49191
                    tls_data['tls_cip'] = tls['TLS Handshake'].cipher_suite
                    # tls compression method 0x00 -> 0
                    tls_data['tls_comp'] = tls['TLS Handshake'].compression_method
                    # tls extensions length 0x8 -> 8
                    tls_data['tls_extlen'] = tls['TLS Handshake'].extensions_length
                    # tls extensions type 0x000b -> 11
                    tls_data['tls_exttype'] = tls['TLS Extension'].type
            return tls_data
        else:
            tls_data['tls_error'] = False
            return tls_data


# SSL/TLS特征
# Note: for 异常处理
def get_ssl_tls_feature(session_pcap, TLSPD):
    pkt_num = 0
    tls_num = 0
    si_sport_di_dport = ""  # sip sport dip dport
    pkt_len = []  # packet length
    tls_len = []  # tls length
    # get tls duration
    for p in session_pcap:
        pkt_num += 1  # Session中packet NO.
        print("\n", "-" * 15, "Packet: %d" % pkt_num, "-" * 15)
        # packet decode
        data_result_dict = TLSPcapDecode.ether_decode(TLSPD, p)
        data_result = json.dumps(data_result_dict, indent=2)  # dict -> str; indent 缩进
        print(data_result)
        si_sport_di_dport = data_result_dict['IP']['source'] + "-" + data_result_dict['IP']['destination']
        pkt_len.append(data_result_dict['len'])
        # return tls info
        try:
            data_result_dict['IP']['TCP']['TLS']
        except KeyError:
            tls_len.append(0)
        else:
            tls_num += 1
            tls_len.append(data_result_dict['IP']['TCP']['TLS']['tls_len'])
            if data_result_dict['IP']['TCP']['TLS']['tls_step'] == 2:
                tls_cip = data_result_dict['IP']['TCP']['TLS']['tls_cip']
                tls_comp = data_result_dict['IP']['TCP']['TLS']['tls_comp']
                tls_extlen = data_result_dict['IP']['TCP']['TLS']['tls_extlen']
                tls_exttype = data_result_dict['IP']['TCP']['TLS']['tls_exttype']
    return si_sport_di_dport, pkt_len, tls_num, tls_len, tls_cip, tls_comp, tls_extlen, tls_exttype


# 会话流统计特征
def get_session_statistic_feature(session_pcap, TLSPD):
    session_statistic_features = dict()
    si_sport_di_dport, pkt_len, tlss_cnt, tls_len, tls_cip, tls_comp, tls_extlen, tls_exttype = get_ssl_tls_feature(
        session_pcap,
        TLSPD)
    session_statistic_features['si_sport_di_dport'] = si_sport_di_dport
    pkts_cnt = len(session_pcap)  # 数据包数量
    session_statistic_features['pkts_cnt'] = pkts_cnt
    if pkts_cnt:
        sessn_dur = session_pcap[pkts_cnt - 1].time - session_pcap[0].time  # Session持续时间
        session_statistic_features['sessn_dur'] = float(sessn_dur)
    total_bytes = sum(pkt_len)  # Session总字节数
    session_statistic_features['total_bytes'] = total_bytes
    pkts_len_avg = total_bytes / (pkts_cnt - 3)  # pactet包长平均值，排除tcp三次握手
    session_statistic_features['pkts_len_avg'] = pkts_len_avg
    total_bytes_tls = sum(tls_len)  # tls总字节数
    session_statistic_features['total_bytes_tls'] = total_bytes_tls
    tlss_len_avg = total_bytes_tls / tlss_cnt
    session_statistic_features['tlss_len_avg'] = tlss_len_avg
    session_statistic_features['tls_cip'] = tls_cip
    session_statistic_features['tls_comp'] = tls_comp
    session_statistic_features['tls_extlen'] = tls_extlen
    session_statistic_features['tls_exttype'] = tls_exttype
    return session_statistic_features


def main():
    TLSPD = TLSPcapDecode()
    session_pcap = rdpcap("tcp_ssl_demo_0.pcap")
    session_statistic_features = get_session_statistic_feature(session_pcap, TLSPD)
    print(session_statistic_features)


if __name__ == '__main__':
    main()
