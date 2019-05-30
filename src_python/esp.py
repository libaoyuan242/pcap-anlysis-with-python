# -*- coding:utf-8 -*-

'''
Created on 2016年1月23日

@author: chch
'''

import tcp
import udp
import stream
from decode_utils import err, hex_string, str_to_int

class ESP():
    def __init__(self,father):
        self.father=father
        self.layer_name='esp'
        self.spi=None,
        self.sequence=None,
        self.pad_length=None,
        self.next_header=None,
        self.auth_data=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None

    def upper_layer_selector(self,protocol_code):
        selector = {
            6: tcp.TCP,
            17: udp.UDP,
        }
        func = selector.get(protocol_code, stream.STREAM)
        return func(self)

    def decode(self,packet_data,length):
        if length<22:
            err("esp decode error: insufficient length: %"%(length))
            return None
        else:
            self.spi=str_to_int(packet_data[0:4], 4)
            self.sequence=str_to_int(packet_data[4:8], 4)
            self.pad_length=ord(packet_data[-14])
            self.next_header=ord(packet_data[-13])
            self.auth_data=packet_data[-12:]
            self.payload=packet_data[8:-14-self.pad_length]
            self.payload_length=length-8-14-self.pad_length
            
            self.payload_layer=self.upper_layer_selector(self.next_header)
            
            if self.payload_layer.decode(self.payload,self.payload_length) == None:
                self.payload_layer=stream.STREAM(self)
                self.payload_layer.decode(self.payload,self.payload_length)

            if self.payload_layer:
                if self.payload_layer.decode(self.payload, self.payload_length)==None:
                    self.payload_layer=None

            return self
            

    
    def __str__(self):
        return "esp(spi=%s, sequence=%s, pad_length=%s, next_header=%s, auth_data=%s, payload_layer=%s)"%(self.spi, self.sequence, self.pad_length, self.next_header, hex_string(self.auth_data,12,''), self.payload_layer)

    def to_dict(self):
        d={}
        d['layer_name']='esp'
        d['spi']=self.spi
        d['sequence']=self.sequence
        d['pad_length']=self.pad_length
        d['next_header']=self.next_header
        d['auth_data']=hex_string(self.auth_data, len(self.auth_data), '')
        d['payload_length']=self.payload_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d
        