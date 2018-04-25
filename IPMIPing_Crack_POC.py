#!/usr/bin/env python
# -*- coding:utf-8 -*-
import socket
import logging


timeout = 3
socket.setdefaulttimeout(timeout)

def STRING_TO_BINARY(content):
    """将文本流转换成二进制流"""
    return content.replace(' ','').replace('\n','').decode('hex')

def SEND_IPMI_PING_PACKET(ip,port=623):
    """
        发送IPMIPING报文，尝试获取响应，大量的该类型报文将导致DRDDoS
        反射流量放大倍数约为1.167倍
        06 -> RMCP Version
        00 -> RMCP Reserved
        FO -> RMCP Sequence Number
        06 -> RMCP Message Class (ASF)
        00 -> ASF IANA
        00 -> ASF IANA
        11 -> ASF IANA
        BE -> ASF IANA
        80 -> Presence Ping
        10 -> ID
        00 -> Resv
        00 -> Resv
    """
    packet_data = "0600F006000011BE80100000"#IPMIPing报文格式
    socks = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)#使用UDP发送
    socks.sendto(STRING_TO_BINARY(packet_data),(ip,port))

    try:
        data,addr = socks.recvfrom(1024)
    except Exception,reason:
        logging.error(reason)
        print "\033[0;32m%s 不存在反射分布式拒绝服务攻击\033[0m"%ip
        return False
    print """\033[0;32m
        [*] 存在反射分布式拒绝服务攻击
        [*] 发送数据大小 : %s
        [*] 接受数据大小 : %s
        [*] 接受对端地址 : %s
    \033[0m"""%(str(len(packet_data)),str(len(data)),str(addr))
    return True

if __name__ == '__main__':
    '''
    72.35.243.40
    124.248.206.30
    213.136.93.207
    74.222.27.163
    176.74.220.112
    185.236.36.146
    64.187.150.171
    76.164.195.210
    107.150.184.170
    198.46.234.214
    46.23.68.37
    nc -v -l -p 623 -u -s 192.168.100.64
    '''
    SEND_IPMI_PING_PACKET(ip='192.168.100.64',port=623)
