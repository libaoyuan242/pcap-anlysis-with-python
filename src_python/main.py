# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''

from time import ctime
from decode_utils import err, with_file_ext

import pymongo
from pcapfile_handler import decode_pcap_file_to_dict
import os



def main():
#     filename='../../pcap_files/voice.pcapng'
#     filename='../../pcap_files/voice1.pcap'
#     filename='../../pcap_files/v1.pcap'
    file_extension_list=['.pcapng','.pcap','cap']
#     path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files'
    path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files\\voice.pcapng'
#     path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files\\new\\IMS_capture_00125_20150325130546.pcap'
#     path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files\\new'
#     path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files\\4_ip_frag_sip.pcap'
#     path_name='C:\\Users\\chch\\Documents\\devel\\python\\workspace\\pcap_files\\2_ipv6_frag_sip.pcap'

    
    if os.path.isdir(path_name):
        filelist=map(lambda x:os.path.join(path_name,x), with_file_ext(os.listdir(path_name),file_extension_list))
    else:
        filelist=[path_name]
    
    client = pymongo.MongoClient("localhost", 27017)
#     db = client.test
#     collection=db.s1u
    db = client['test']
    collection=db['s1u_demo']
    collection.drop()
    
    for filename in filelist:
        err("[%s] start to processing file'%s'"%(ctime(), filename))
        packet_list=decode_pcap_file_to_dict(filename)
    
        err('[%s] inserting packets into database'%(ctime()))
        collection.insert(packet_list)
#         n=0
#         for i in packet_list:
#             n=n+1
#             err(n)
#             collection.insert(i)
        err('[%s] pcap file processing finished, total %s packets'%(ctime(), len(packet_list)))
    
    collection.ensure_index("ts_in_second")

if __name__ == '__main__':
    main()

