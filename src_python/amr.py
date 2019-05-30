# -*- coding:utf-8 -*-

'''
Created on 2016年1月20日

@author: chch
'''

import sys
from decode_utils import *
import stream

class AMR_WB():
    def __init__(self,father):
        self.father=father
        self.layer_name='amr_wb'
        self.cmr=None
        self.reserved=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
    
    def decode(self,packet_data,length):
        if length<1 :
            print >> sys.stderr, "amr_wb decode error:insufficient length", length
            return None
        self.cmr=(ord(packet_data[0])&0xf0)>>4
        self.reserved=ord(packet_data[0])&0x0f
        self.payload=packet_data[1:]
        self.payload_length=length-1

        pkt=stream.STREAM(self)
        if pkt.decode(self.payload, self.payload_length)!=None:
            self.payload_layer=pkt
        else:
            self.payload_layer=None
        
        return self
        
    def __str__(self):
        return "amr_wb(cmr=%s, payload_length=%s, payload_layer=%s)"%(self.version,self.padding,self.extension,self.contributing_source_identifiers_count,self.marker,self.payload_type,self.seq_number,self.timestamp,self.sync_source_identifier,str_payload_layer(self.payload_layer))
    
    def to_dict(self):
        d={}
        d['layer_name']='amr_wb'
        d['cmr']=self.cmr
        d['reserved']=self.reserved
#         d['payload']=self.payload
        d['payload_length']=self.payload_length
        
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d
       