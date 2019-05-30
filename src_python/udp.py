# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
from decode_utils import err, str_payload_layer, str_to_int
import gtpu
import rtp
import stream
import sip
from services import services


class UDP():
    
    def __init__(self,father):
        self.father=father
        self.layer_name='udp'
        self.src_port=None
        self.dst_port=None
        self.length=None
        self.checksum=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
        
        
    def decode(self,packet_data,length):
        if length<8:
            err("udp decode error:insufficient length: %s"%(length))
            return None
#         self.src_port=ord(packet_data[0])*256+ord(packet_data[1])
#         self.dst_port=ord(packet_data[2])*256+ord(packet_data[3])
#         self.length=ord(packet_data[4])*256+ord(packet_data[5])
        self.src_port=str_to_int(packet_data[:2],2)
        self.dst_port=str_to_int(packet_data[2:4],2)
        self.length=str_to_int(packet_data[4:6],2)
        if self.length>length:
            err("udp decode error: udp.length(%s) > total_length(%s)"%(self.length, length))
            return None
            
#         self.checksum=ord(packet_data[6])*256+ord(packet_data[7])
        self.checksum=str_to_int(packet_data[6:8],2)
        self.payload=packet_data[8:]
        self.payload_length=length-8
        
        if self.dst_port==2152:
            pkt=gtpu.GTPU(self)
        elif self.dst_port==1234 or self.src_port==1234:
            pkt=rtp.RTP(self)
        elif self.dst_port in services.sip_ports or self.src_port in services.sip_ports:
            pkt=sip.SIP(self)
        else:
            pkt=stream.STREAM(self)
            
        if pkt!=None:
            if pkt.decode(self.payload, self.payload_length)!=None:
                self.payload_layer=pkt
            else:
#                 err("payload_layer decode is None") ## for test!!
                self.payload_layer=None
        return self

    def __str__(self):
        return "udp(src_port=%s, dst_port=%s, payload_layer=%s)"%(str(self.src_port),str(self.dst_port),str_payload_layer(self.payload_layer))


    def to_dict(self):
        d={}
        d['layer_name']='udp'
        d['src_port']=self.src_port
        d['dst_port']=self.dst_port
        d['length']=self.length
        d['checksum']=self.checksum
        d['payload_length']=self.payload_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
            
        return d
        