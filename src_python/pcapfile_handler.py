# -*- coding:utf-8 -*-

'''
Created on 2016年2月5日

@author: chch
'''

import pcap_decoder
import pcapng_decoder
from decode_utils import err


def decode_pcap_file_to_dict(filename):
    fileformat=None
    packet_list=[]
    packet_sqn=0

    with open(filename, 'rb') as fp:
        magic=fp.read(4)
        if magic=='\x0a\x0d\x0d\x0a':
#             err('it is an pcapng file')
            fileformat='pcapng'
        elif magic=='\xa1\xb2\xc3\xd4' or magic=='\xd4\xc3\xb2\xa1':
#             err('it is a pcap file')
            fileformat='pcap'
        else:
            err('unknown format file, magic(%s)'%(list(magic)))
            fileformat='unknown'
    
    with open(filename,'rb') as fp:
        header=None
        idb=None
            
        if fileformat=='pcapng':
            for block in pcapng_decoder.pcapng(fp):
                if isinstance(block, pcapng_decoder.section_header_block):
                    header=block
#                     err(block)
                elif isinstance(block, pcapng_decoder.interface_description_block):
                    idb=block
#                     err(block)
                elif isinstance(block, pcapng_decoder.interface_statistics_block):
#                     err(block)
                    pass
                elif isinstance(block, pcapng_decoder.simple_packet_block):
#                     err(block)
                    pass
                elif isinstance(block, pcapng_decoder.name_resolution_block):
#                     err(block)
                    pass
                elif isinstance(block, pcapng_decoder.enhanced_packet_block):
                    packet_sqn+=1
#                     print packet_sqn,
                    packet_list.append(block.to_dict(idb))
                else:
                    err('unknown block')
                    return
        elif fileformat=='pcap':
            for block in pcap_decoder.pcap(fp):
                if isinstance(block, pcap_decoder.pcap_header):
                    header=block
#                     err(block)
                elif isinstance(block, pcap_decoder.pcap_record):
                    packet_sqn+=1
#                     print "!!!!!!!!!!!!!!!!!!!!!!!!!!!",packet_sqn
                    packet_list.append(block.to_dict(header))
                else:
                    err('unknown block')
                    return
        else:
            err('unknown format, do not processing this file')
    return packet_list
