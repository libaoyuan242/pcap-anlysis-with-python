# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
import ip
from decode_utils import str_to_int, hex_string, str_payload_layer



class ETHER():
    def __init__(self,father):
        self.father=father
        self.layer_name='ether'
        self.dst=None
        self.dst_lg_bit=None
        self.dst_ig_bit=None
        self.src=None
        self.src_lg_bit=None
        self.src_ig_bit=None
        self.type=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
        
    def upper_layer_selector(self,protocol_code):
        selector = {
            0x800: ip.IPV4,
            0x86dd: ip.IPV6,
        }
        # Get the function from switcher dictionary
        func = selector.get(protocol_code, lambda x: None)
        # Execute the function
        return func(self)
    
    
    def decode(self,packet_data,length):
        if length<14:
            print >> sys.stderr, "ether decode error: insufficient length", length
            return None
        self.dst=packet_data[:6]
        self.dst_lg_bit=(ord(self.dst[0])&0x02)>>1
        self.dst_ig_bit=ord(self.dst[0])&0x01
        self.src=packet_data[6:12]
        self.src_lg_bit=(ord(self.src[0])&0x02)>>1
        self.src_ig_bit=ord(self.src[0])&0x01
        if str_to_int(packet_data[12:14], 2)==0x8100:   # if it is an 802.1q frame
            length_1q=2
        else:
            length_1q=0
        self.type=str_to_int(packet_data[12+length_1q:14+length_1q], 2)
        self.payload=packet_data[14+length_1q:]
        self.payload_length=length-14-length_1q
        
        self.payload_layer=self.upper_layer_selector(self.type)
        if self.payload_layer:
            self.payload_layer.decode(self.payload, self.payload_length)

        return self

    
    def __str__(self):
        return "ether(dst=%s, src=%s, type=%s, payload_layer=%s)"%(hex_string(self.dst,6,':'),hex_string(self.src, 6, ':'),hex(self.type),str_payload_layer(self.payload_layer))

    def to_dict(self):
        d={}
        d['layer_name']='ether'
        d['dst']=hex_string(self.dst,6,':')
        d['src']=hex_string(self.src, 6, ':')
        d['type']=self.type
        
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d
        