#!/usr/bin/env python
# -*- coding: utf-8 -*-

__Author__ = "SewellDing"

from scapy.all import *
from datetime import datetime


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
            # ls(tls)
            # tls.show()
            try:
                tls['TLS Record']
            except IndexError:
                tls_data['tls_vers'] = 771
                tls_data['tls_len'] = -1  # 待处理
            else:
                tls_data['tls_vers'] = tls['TLS Record'].version
                tls_data['tls_len'] = tls['TLS Record'].length
            # get tls duration
            # get ssl/tls stage 2 features
            try:
                tls['TLS Handshake']
            except IndexError:
                tls_data['tls_step'] = -1
            else:
                tls_data['tls_step'] = tls['TLS Handshake'].type
                # stage 2: Server Hello
                if tls_data['tls_step'] == 2:
                    tls_data['tls_cip'] = tls['TLS Handshake'].cipher_suite
                    tls_data['tls_comp'] = tls['TLS Handshake'].compression_method
                    tls_data['tls_extlen'] = tls['TLS Handshake'].extensions_length
                    tls_data['tls_exttype'] = tls['TLS Extension'].type
            return tls_data
        else:
            tls_data['tls_error'] = False
            return tls_data


# SSL/TLS特征
def get_ssl_tls_feature(session_pcap, TLSPD):
    si_sport_di_dport = ""
    pkt_len = []
    tls_len = []
    pkt_num = tls_num = tls_vers = tls_cip = tls_comp = tls_extlen = tls_exttype = 0
    for p in session_pcap:
        # p.show()
        pkt_num += 1
        data_result_dict = TLSPcapDecode.ether_decode(TLSPD, p)
        try:
            si_sport_di_dport = data_result_dict['IP']['source'] + "-" + data_result_dict['IP']['destination']
        except TypeError:
            # Note: 异常未处理
            pass
        else:
            si_sport_di_dport = data_result_dict['IP']['source'] + "-" + data_result_dict['IP']['destination']
        # 包长度值添加至列表
        pkt_len.append(data_result_dict['len'])
        try:
            data_result_dict['IP']['TCP']['TLS']
        except KeyError:
            tls_len.append(0)
        except TypeError:
            pass
        else:
            tls_num += 1
            if data_result_dict['IP']['TCP']['TLS']['tls_step'] == 1:
                tls_vers = data_result_dict['IP']['TCP']['TLS']['tls_vers']
            if data_result_dict['IP']['TCP']['TLS']['tls_step'] == 2:
                tls_cip = data_result_dict['IP']['TCP']['TLS']['tls_cip']
                tls_comp = data_result_dict['IP']['TCP']['TLS']['tls_comp']
                tls_extlen = data_result_dict['IP']['TCP']['TLS']['tls_extlen']
                tls_exttype = data_result_dict['IP']['TCP']['TLS']['tls_exttype']
            tls_len.append(data_result_dict['IP']['TCP']['TLS']['tls_len'])
    return si_sport_di_dport, pkt_len, tls_vers, tls_num, tls_len, tls_cip, tls_comp, tls_extlen, tls_exttype


# 会话流统计特征
def get_session_statistic_feature(session_pcap, TLSPD):
    get_feature = []
    pkts_len_avg = tlss_len_avg = 0
    si_sport_di_dport, pkt_len, tls_vers, tlss_cnt, tls_len, tls_cip, tls_comp, tls_extlen, tls_exttype = get_ssl_tls_feature(
        session_pcap,
        TLSPD)
    get_feature.append(si_sport_di_dport)
    # 数据包数量
    pkts_cnt = len(session_pcap)
    get_feature.append(pkts_cnt)
    if pkts_cnt:
        # Session持续时间
        sessn_dur = session_pcap[pkts_cnt - 1].time - session_pcap[0].time
        get_feature.append(float(sessn_dur))
    # Session总字节数
    total_bytes = sum(pkt_len)
    get_feature.append(total_bytes)
    if pkts_cnt > 3:
        # pactet包长平均值，排除tcp三次握手
        pkts_len_avg = total_bytes / (pkts_cnt - 3)
    get_feature.append(pkts_len_avg)
    # tls总字节数
    total_bytes_tls = sum(tls_len)
    get_feature.append(total_bytes_tls)
    if tlss_cnt != 0:
        # tls包长平均值
        tlss_len_avg = total_bytes_tls / tlss_cnt
    get_feature.append(tlss_len_avg)
    get_feature.append(tls_cip)
    get_feature.append(tls_comp)
    get_feature.append(tls_extlen)
    get_feature.append(tls_exttype)
    get_feature.append(tls_vers)
    return get_feature
