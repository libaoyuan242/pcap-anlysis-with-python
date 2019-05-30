# -*- coding:utf-8 -*-

'''
Created on 2016年1月24日

@author: chch
'''

import udp
import tcp
import esp
import stream
from ip_fragment_set import IP_FRAGMENT_SET

from decode_utils import (err, str_to_int)

class IPV6_FRAGMENT():

    def __init__(self, father):
        '''
        Constructor
        '''
        self.father=father
        self.layer_name='ipv6_fragment'
        self.next_header=None
        self.offset=None
        self.more_fragments=None
        self.identification=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
        
        self.timeout=3

    def upper_layer_selector(self,protocol_code):
        selector = {
            6: tcp.TCP,
            17: udp.UDP,
            50: esp.ESP
        }
        func = selector.get(protocol_code, stream.STREAM)
        return func(self)



        
    def decode(self,packet_data,length):
        
        if length <8:
            err("ipv6_fragment decode error: insufficient length(%s)"%(length))
            return None
        self.next_header=ord(packet_data[0])
        self.offset=(ord(packet_data[2])<<5)+(ord(packet_data[3])>>3)
        self.more_fragments=ord(packet_data[3])&0x01
        self.identification=str_to_int(packet_data[4:8], 4)
        self.payload=packet_data[8:]
        self.payload_length=length-8
        
#         print "1",IP_FRAGMENT_SET.set
        data=IP_FRAGMENT_SET.combine(self)
#         print "2",IP_FRAGMENT_SET.set
#         print data
        if data!=None:
            self.payload,self.payload_length=data
            self.payload_layer=self.upper_layer_selector(self.next_header)
        else:
            self.payload_layer=stream.STREAM(self)
        
        if self.payload_layer.decode(self.payload, self.payload_length)==None:
            self.payload_layer=None
            

        return self
    
    
    
    
    def __str__(self):
        '''
        '''
        return "ipv6_fragment(%s)"%(self.next_header,self.offset,self.more_fragments,self.identification)
    
    def to_dict(self):
        d={}
        d['layer_name']='ipv6_fragment'
        d['next_header']=self.next_header
        d['offset']=self.offset
        d['more_fragments']=self.more_fragments
        d['identification']=self.identification
        d['payload_length']=self.payload_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
            
        return d
        
        