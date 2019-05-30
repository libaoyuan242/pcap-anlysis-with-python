# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''

import tcp
import udp
import esp
import stream
from decode_utils import err, dec_string, str_payload_layer, hex_string, str_to_int
import ipv6_fragment
from ip_fragment_set import IP_FRAGMENT_SET

class IPV4():
    def __init__(self,father):
        self.father=father
        self.layer_name='ipv4'
        self.version=None,
        self.header_length=None,
        self.diff_service_field=None,
        self.total_length=None,
        self.id=None
        self.flags=None
        self.dont_fragment=None
        self.more_fragments=None
        self.fragment_offset=None
        self.ttl=None
        self.protocol=None
        self.header_checksum=None
        self.src=None
        self.dst=None
        self.options=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None

    def upper_layer_selector(self,protocol_code):
        selector = {
            6: tcp.TCP,
            17: udp.UDP,
        }
        # Get the function from switcher dictionary
        func = selector.get(protocol_code, stream.STREAM)
        # Execute the function
        return func(self)

    def decode(self,packet_data,length):
        if length<20:
            err("ipv4 decode error: insufficient length(%s)"%(length))
            return None
        else:
            self.version=ord(packet_data[0])>>4
            self.header_length=(ord(packet_data[0])&0x0f)*4
            if length < self.header_length:
                err("ipv4 header decode error:insufficient length(%s)"%(length))
                return None
            self.diff_service_field=ord(packet_data[1])
            self.total_length=ord(packet_data[2])*256+ord(packet_data[3])
            self.id=ord(packet_data[4])*256+ord(packet_data[5])
            self.flags=ord(packet_data[6])>>5
            self.dont_fragment=(self.flags&0x02)>>1
            self.more_fragments=self.flags&0x01
            self.fragment_offset=(ord(packet_data[6])&0x1f)*256+ord(packet_data[7])
            self.ttl=ord(packet_data[8])
            self.protocol=ord(packet_data[9])
            self.header_checksum=ord(packet_data[10])*256+ord(packet_data[11])
            self.src=packet_data[12:16]
            self.dst=packet_data[16:20]
            self.options=packet_data[20:self.header_length]
            self.payload=packet_data[self.header_length:]
            self.payload_length=length-self.header_length
            if self.payload_length>len(self.payload):
                return None
            
            if self.more_fragments==0 and self.fragment_offset==0:
                self.payload_layer=self.upper_layer_selector(self.protocol)
            else:   ## should be check with queued ip fragments. now we just take it as a stream
                data=IP_FRAGMENT_SET.combine(self)
                if data!=None:
                    self.payload,self.payload_length=data
                    self.payload_layer=self.upper_layer_selector(self.protocol)
                else:
                    self.payload_layer=stream.STREAM(self)

            if self.payload_layer:
                if self.payload_layer.decode(self.payload, self.payload_length)==None:
                    self.payload_layer=None

            return self
            

    
    def __str__(self):
        return "ipv4(version=%s, src=%s, dst=%s, protocol=%s, payload_layer=%s)"%(str(self.version),dec_string(self.src,4,'.'),dec_string(self.dst, 4, '.'),self.protocol,str_payload_layer(self.payload_layer))

    def to_dict(self):
        d={}
        d['layer_name']='ipv4'
        d['version']=self.version
        d['header_length']=self.header_length
        d['diff_service_field']=self.diff_service_field
        d['total_length']=self.total_length
        d['id']=self.id
        d['flags']=self.flags
        d['dont_fragment']=self.dont_fragment
        d['more_fragments']=self.more_fragments
        d['fragment_offset']=self.fragment_offset
        d['ttl']=self.ttl
        d['protocol']=self.protocol
        d['header_checksum']=self.header_checksum
        d['src']=dec_string(self.src,4,'.')
        d['dst']=dec_string(self.dst,4,'.')
        d['options']=self.options
        d['payload_length']=self.payload_length

        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d

class IPV6():
    def __init__(self,father):
        self.father=father
        self.layer_name='ipv6'
        self.version=None,
        self.traffic_class=None
        self.tc_diff_service_codepoint=None,
        self.tc_explicit_congestion_notification=None
        self.flow_label=None
        self.payload_length_h=None
        self.next_header=None
        self.hop_limit=None
        self.src=None
        self.dst=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None

    def upper_layer_selector(self,protocol_code):
        selector = {
            6: tcp.TCP,
            17: udp.UDP,
            44: ipv6_fragment.IPV6_FRAGMENT,
            50: esp.ESP
        }
        func = selector.get(protocol_code, stream.STREAM)
        return func(self)

        
    def decode(self,packet_data,length):
        if length<40:
            err("ipv6 decode error: insufficient length(%s)"%(length))
            return None
        else:
            self.version=ord(packet_data[0])>>4
            self.traffic_class=((ord(packet_data[0])&0x0f)<<4)+((ord(packet_data[1])&0xf0)>>4)
            self.tc_diff_service_codepoint=self.traffic_class >> 2
            self.tc_explicit_congestion_notification=self.traffic_class & 0x3
            self.flow_label=(ord(packet_data[1])&0x0f)*65536+str_to_int(packet_data[2:4], 2)
            self.payload_length_h=str_to_int(packet_data[4:6], 2)
            self.next_header=ord(packet_data[6])
            self.hop_limit=ord(packet_data[7])
            self.src=packet_data[8:24]
            self.dst=packet_data[24:40]
            
            self.payload_length=length-40
            self.payload=packet_data[40:]
            if self.payload_length>len(self.payload):
                return None
            
            self.payload_layer = self.upper_layer_selector(self.next_header)
                
            if self.payload_layer.decode(self.payload, self.payload_length) ==None:
                self.payload_layer=None

            return self

    def __str__(self):
        return "ipv6(version=%s, src=%s, dst=%s, next_header=%s, payload_layer=%s)"%(str(self.version),hex_string(self.src,16,''),hex_string(self.dst, 16, ''),self.next_header,str_payload_layer(self.payload_layer))


    def to_dict(self):
        d={}
        d['layer_name']='ipv6'
        d['version']=self.version
        d['traffic_class']=self.traffic_class
        d['tc_diff_service_codepoint']=self.tc_diff_service_codepoint
        d['tc_explicit_congestion_notification']=self.tc_explicit_congestion_notification
        d['flow_label']=self.flow_label
        d['payload_length_h']=self.payload_length_h
        d['next_header']=self.next_header
        d['hop_limit']=self.hop_limit
        d['src']=hex_string(self.src,16,'')
        d['dst']=hex_string(self.dst,16,'')
        
        d['payload_length']=self.payload_length
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d
