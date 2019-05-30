# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
from decode_utils import str_payload_layer, str_to_int, err
import tcp_segment


class TCP():
    def __init__(self,father):
        self.father=father
        self.layer_name='tcp'
        self.src_port=None
        self.dst_port=None
        self.seq_number=None
        self.ack_number=None
        self.header_length=None
        self.flags=None
        self.flag_urg=None
        self.flag_ack=None
        self.flag_psh=None
        self.flag_rst=None
        self.flag_syn=None
        self.flag_fin=None
        self.window_size=None
        self.checksum=None
        self.urgent_pointer=None
        self.options=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
        
    def decode(self,packet_data,length):
        if length<20:
            err("tcp decode error:insufficient length(%s)"%(length))
            return None
        self.src_port=str_to_int(packet_data[:2], 2)
        self.dst_port=str_to_int(packet_data[2:4], 2)
        self.seq_number=str_to_int(packet_data[4:8], 4)
        self.ack_number=str_to_int(packet_data[8:12], 4)
        self.header_length=(ord(packet_data[12])>>4)*4
        if length < self.header_length:
            err("tcp header decode error:insufficient length(%s)"%(length))
            return None
        
        self.flags=ord(packet_data[13])&0x3f
        self.flag_urg=(self.flags>>5)&0x1
        self.flag_ack=(self.flags>>4)&0x1
        self.flag_psh=(self.flags>>3)&0x1
        self.flag_rst=(self.flags>>2)&0x1
        self.flag_syn=(self.flags>>1)&0x1
        self.flag_fin=self.flags&0x1

        self.window_size=str_to_int(packet_data[14:16], 2)
        self.checksum=str_to_int(packet_data[16:18], 2)
        self.urgent_pointer=str_to_int(packet_data[18:20], 2)
        self.options=packet_data[20:self.header_length]
        self.payload=packet_data[self.header_length:]
        self.payload_length=length-self.header_length
        self.payload_layer=None # to be changed later
        
        if self.flag_psh!=0 or self.payload_length>0:
            pkt=tcp_segment.TCP_SEGMENT(self)
            if pkt.decode(self.payload, self.payload_length)!=None:
                self.payload_layer=pkt
            else:
                self.payload_layer=None
        else:
            self.payload_layer=None
        
        return self


    def __str__(self):
        return "tcp(src_port=%s, dst_port=%s, seq_number=%s, payload_layer=%s)"%(str(self.src_port),str(self.dst_port),str(self.seq_number),str_payload_layer(self.payload_layer))

    def to_dict(self):
        d={}
        d['layer_name']='tcp'
        d['src_port']=self.src_port
        d['dst_port']=self.dst_port
        d['seq_number']=self.seq_number
        d['ack_number']=self.ack_number
        d['header_length']=self.header_length
        d['flags']=self.flags
        
        d['flag_urg']=self.flag_urg
        d['flag_ack']=self.flag_ack
        d['flag_psh']=self.flag_psh
        d['flag_rst']=self.flag_rst
        d['flag_syn']=self.flag_syn
        d['flag_fin']=self.flag_fin
        
        d['window_size']=self.window_size
        d['checksum']=self.checksum
        d['urgent_pointer']=self.urgent_pointer
        d['payload_length']=self.payload_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
            
        return d
        