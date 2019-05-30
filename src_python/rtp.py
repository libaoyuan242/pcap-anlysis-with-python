# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
from decode_utils import err, str_payload_layer, str_to_int
import amr

class RTP():
    def __init__(self,father):
        self.father=father
        self.layer_name='rtp'
        self.version=None
        self.padding=None
        self.extension=None
        self.contributing_source_identifiers_count=None
        self.marker=None
        self.payload_type=None
        self.seq_number=None
        self.timestamp=None
        self.sync_source_identifier=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
    
    def decode(self,packet_data,length):
        if length<12 :
            err("rtp decode error:insufficient length(%s)"%(length))
            return None
        self.version=(ord(packet_data[0])&0xc0)>>6
        self.padding=(ord(packet_data[0])&0x20)>>5
        self.extension=(ord(packet_data[0])&0x10)>>4
        self.contributing_source_identifiers_count=ord(packet_data[0])&0x0f
        self.marker=(ord(packet_data[1])&0x80)>>7
        self.payload_type=ord(packet_data[1])&0x7f
        self.seq_number=str_to_int(packet_data[2:4], 2)
        self.timestamp=str_to_int(packet_data[4:8], 4)
        self.sync_source_identifier=str_to_int(packet_data[8:12], 4)
        self.payload=packet_data[12:]
        self.payload_length=length-12
        
        if self.payload_type>=96:
            pkt=amr.AMR_WB(self)
            if pkt.decode(self.payload, self.payload_length)!=None:
                self.payload_layer=pkt
            else:
                self.payload_layer=None
        return self
    
        
    def __str__(self):
        return "rtp(version=%s, padding=%s, extension=%s, contributing_source_identifiers_count=%s, marker=%s, payload_type=%s, seq_number=%s, timestamp=%s, sync_source_identifier=%s, payload_layer=%s)"%(self.version,self.padding,self.extension,self.contributing_source_identifiers_count,self.marker,self.payload_type,self.seq_number,self.timestamp,self.sync_source_identifier,str_payload_layer(self.payload_layer))
    
    def to_dict(self):
        d={}
        d['layer_name']='rtp'
        d['version']=self.version
        d['padding']=self.padding
        d['extension']=self.extension
        d['contributing_source_identifiers_count']=self.contributing_source_identifiers_count
        d['marker']=self.marker
        d['payload_type']=self.payload_type
        d['seq_number']=self.seq_number
        d['timestamp']=self.timestamp
        d['sync_source_identifier']=self.sync_source_identifier
        d['seq_number']=self.seq_number
        d['payload_length']=self.payload_length
        
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
            
        return d
        