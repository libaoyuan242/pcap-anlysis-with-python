# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
import sys
from decode_utils import *
import ip

class GTPU():
    def __init__(self,father):
        self.father=father
        self.layer_name='gtpu'
        self.flags=None
        self.flag_version=None
        self.flag_protocol_type=None
        self.flag_is_next_extension_header_present=None
        self.flag_is_seq_number_present=None
        self.flag_is_n_pdu_number_present=None
        self.message_type=None
        self.length=None
        self.teid=None
        self.seq_number=None
        self.n_pdu_number=None
        self.extension_list=None
        self.t_pdu=None
        self.t_pdu_length=None
        self.payload_layer=None
        
    def upper_layer_selector(self,protocol_code):
        selector = {
            4: ip.IPV4,
            6: ip.IPV6,
        }
        # Get the function from switcher dictionary
        func = selector.get(protocol_code, lambda: None)
        # Execute the function
        return func(self)
    
    def decode(self,packet_data,length):
        i=0
        if length<8:
            print >> sys.stderr, "gtpu decode error:insufficient length", length
            return None
        self.flags=packet_data[0]
        self.flag_version=(ord(self.flags)&0xe0)>>5
        self.flag_protocol_type=(ord(self.flags)&0x10)>>4
        self.flag_is_next_extension_header_present=(ord(self.flags)&0x04)>>2
        self.flag_is_seq_number_present=(ord(self.flags)&0x02)>>1
        self.flag_is_n_pdu_number_present=ord(self.flags)&0x01
        i+=1
        self.message_type=ord(packet_data[i])
        i+=1
        self.length=str_to_int(packet_data[i:i+2], 2)
        i+=2
        self.teid=str_to_int(packet_data[i:i+4],4)
        i+=4
        if self.flag_is_seq_number_present>0 or self.flag_is_next_extension_header_present>0 or self.flag_is_n_pdu_number_present>0:
            self.seq_number=str_to_int(packet_data[i:i+2], 2)
            i+=2
        if self.flag_is_seq_number_present>0 or self.flag_is_next_extension_header_present>0 or self.flag_is_n_pdu_number_present>0:
            self.n_pdu_number=ord(packet_data[i])
            i+=1
        if self.flag_is_seq_number_present>0 or self.flag_is_next_extension_header_present>0 or self.flag_is_n_pdu_number_present>0:
            while(ord(packet_data[i])!=0):
                extension_header_type=ord(packet_data[i])
                extension_header_length=ord(packet_data[i+1])
                extension_header_value=packet_data[i+2:i+2+extension_header_length]
                self.extension_list.append((extension_header_type,extension_header_length,extension_header_value))
                i+=(2+extension_header_length)
            i+=1
        if self.message_type==0xff :
            self.t_pdu=packet_data[i:]
            self.t_pdu_length=length-i
            ip_version=ord(self.t_pdu[0])>>4
            
            self.payload_layer=self.upper_layer_selector(ip_version)
            if self.payload_layer:
                self.payload_layer.decode(self.t_pdu, self.t_pdu_length)
            ## else: ???
        return self
    
    def __str__(self):
        return "gtpu(flag_version=%s, flag_protocol_type=%s, message_type=%s, length=%s, teid=%s, payload_layer=%s)"%(str(self.flag_version),str(self.flag_protocol_type),str(self.message_type),str(self.length),hex(self.teid),str_payload_layer(self.payload_layer))

    def to_dict(self):
        
        d={}
        d['layer_name']='gtpu'
        d['flags']=self.flags
        d['flag_version']=self.flag_version
        d['flag_protocol_type']=self.flag_protocol_type
        d['flag_is_next_extension_header_present']=self.flag_is_next_extension_header_present
        d['flag_is_seq_number_present']=self.flag_is_seq_number_present
        d['flag_is_n_pdu_number_present']=self.flag_is_n_pdu_number_present
        d['message_type']=self.message_type
        d['length']=self.length
        d['teid']=self.teid
        d['seq_number']=self.seq_number
        d['n_pdu_number']=self.n_pdu_number
        d['extension_list']=self.extension_list
        d['t_pdu_length']=self.t_pdu_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d
        