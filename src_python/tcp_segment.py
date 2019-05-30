# -*- coding:utf-8 -*-

'''
Created on 2016年2月6日

@author: chch
'''
from services import services
import sip
import stream
from decode_utils import err, str_payload_layer, dec_string, hex_string


class TCP_SEGMENT_SET(object):
    '''
    classdocs
    '''
    set={}
    timeout=5
    


    def __init__(self, params):
        '''
        Constructor
        '''
        pass

    @classmethod
    def find_ip_addr(cls,obj):
        if obj.layer_name=='ipv4':
            return (obj.src, obj.dst)
        elif obj.layer_name=='ipv6':
            return (obj.src, obj.dst)
        else:
            return cls.find_ip_addr(obj.father)
    
    @classmethod
    def make_protocol_layer_name(cls,obj):
        if obj.layer_name=='gtpu':
            return 'gtpu(teid(%s))'%(obj.teid)
        else:
            return obj.layer_name

    
    @classmethod
    def make_protocol_stack_key(cls,obj):
        if obj==None:
            return 'root'
        elif obj.layer_name=='ipv6_fragment':                       ## skip fragment layer in key
            return "%s"%(cls.make_protocol_stack_key(obj.father))   ## skip fragment layer in key
        else:
            return "%s.%s"%(cls.make_protocol_stack_key(obj.father),cls.make_protocol_layer_name(obj))
    
    @classmethod
    def make_tcp_segment_info_key(cls,obj):
        return "ip.src=%s,ip.dst=%s,src_port=%s,dst_port=%s"%(obj.ip_src,obj.ip_dst,obj.src_port, obj.dst_port)
    
    @classmethod
    def make_tcp_segment_set_key(cls,obj):
        return "((%s),(%s))"%(cls.make_protocol_stack_key(obj),cls.make_tcp_segment_info_key(obj))
    
    @classmethod
    def sort_by_sqn_number(cls,seg_list):
        return sorted(seg_list,key=lambda seg: seg.seq_number)

    @classmethod
    def get_timestamp(cls,obj):
        if obj==None:
            return None
        elif obj.layer_name=='enhanced_packet':
            return obj.ts_in_second
        else:
            return cls.get_timestamp(obj.father)
        
    @classmethod
    def remove_timeout_items(cls,seg_list,obj):
        new_seg_list=[]
        ts=cls.get_timestamp(obj)
        for item in seg_list:
            if cls.get_timestamp(item) >= ts-cls.timeout:
                new_seg_list.append(item)
        return new_seg_list
    
    
    @classmethod
    def get_seg_list(cls,obj):
        key=cls.make_tcp_segment_set_key(obj)
        if key in cls.set:
            tcp_seg_list=cls.set[key]
            tcp_seg_list=cls.remove_timeout_items(tcp_seg_list,obj)
            tcp_seg_list=cls.sort_by_sqn_number(tcp_seg_list)
            return tcp_seg_list
        else:
            return []


class TCP_SEGMENT(object):
    '''
    TCP_DATA classdocs
    ip.src
    ip.dst
    tcp.sport
    tcp.dport
    tcp.seq_number
    tcp.payload_length
    proto_stack
    
    key=proto_stack+ip.src+ip.dst+tcp.sport+tcp.dport
    obj[n+1].tcp.seq_number=obj[n].tcp.seq_number+obj[n].tcp.payload_length
    tcp.payload can be decoded as a complete SIP message
    
    when a tcp object is received:
        if its payload can be decoded as a complete SIP message:
            assign the payload layer as the decoded SIP object
        else:
            assign the payload layer as a STREAM object
            get object list with the same key as the tcp object from the collection set
            add the tcp object to the object list
            if the payload parts of the object list can be combined and the combined payload can be decoded as a SIP packet:
                remove the object list with key from the collection set
                return the assembled SIP message
            else:
                return a STREAM object as the payload of the tcp object
    '''

    def __init__(self, father):
        '''
        Constructor
        '''
        self.father=father
        self.layer_name='tcp_segment'
        self.src_port=None
        self.dst_port=None
        self.ip_src=None
        self.ip_dst=None
        self.seq_number=None
        self.ack_number=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
    
    def find_prev_tcp_seg(self,seq_number,tcp_seg_list):
        for seg in tcp_seg_list:
            if (seg.seq_number+seg.payload_length)==seq_number:
                return seg
        return None
        
    
    def decode_sip_with_tcp_seg_list(self, seq_number, payload, payload_length, tcp_seg_list, used_tcp_seg_list):
        if tcp_seg_list==[]:
            return None,[]
        else:
            prev_seg=self.find_prev_tcp_seg(seq_number, tcp_seg_list)
            if prev_seg==None:
                return None,tcp_seg_list
            else:
                tcp_seg_list.remove(prev_seg)
                new_payload=prev_seg.payload+payload
                new_payload_length=prev_seg.payload_length+payload_length

                pkt=sip.SIP(self)
                if pkt.decode(new_payload, new_payload_length)!=None:
                    return pkt,tcp_seg_list+used_tcp_seg_list
                else:
#                     return self.decode_sip_with_tcp_seg_list(prev_seg.sqn_number, new_payload, new_payload_length, tcp_seg_list,used_tcp_seg_list+[prev_seg])
                    return self.decode_sip_with_tcp_seg_list(prev_seg.seq_number, new_payload, new_payload_length, tcp_seg_list,used_tcp_seg_list)
#             
#             
#             
#             seg_list0=tcp_seg_list
#             seg_list1=[]
#             
#         for seg in tcp_seg_list:
#             
#             if self.seq_number==seg.seq_number+seg.payload_length:
#                 data=seg.payload+self.payload
#                 length=seg.payload_length+self.payload_length
#                 pkt=sip.SIP(self)
#                 if pkt.decode(data, length)!=None:
#                     self.payload_layer=pkt
#                     tcp_seg_list.remove(seg)
#                     if len(tcp_seg_list)>0:
#                         TCP_SEGMENT_SET.set[key]=tcp_seg_list
#                     else:
#                         del TCP_SEGMENT_SET.set[key]
#                     return self
                    
#     @classmethod
    def decode_sip(self,payload,payload_length):
        key=TCP_SEGMENT_SET.make_tcp_segment_set_key(self)
        pkt=sip.SIP(self)
        if pkt.decode(payload, payload_length) != None:
#             self.payload_layer=pkt
            return pkt
        else:
            tcp_seg_list=TCP_SEGMENT_SET.get_seg_list(self)
            
            pkt,rest_tcp_seg_list=self.decode_sip_with_tcp_seg_list(self.seq_number, payload, payload_length, tcp_seg_list,[])
            if pkt !=None:
                self.payload_layer=pkt
#                 print pkt
                TCP_SEGMENT_SET.set[key]=rest_tcp_seg_list
                return pkt
            else:
                TCP_SEGMENT_SET.set[key]=rest_tcp_seg_list+[self]
                return None
            
            
            
            
########################################################################################    

        
        pass
    
    def decode(self,packet_data,length):
        self.src_port=self.father.src_port
        self.dst_port=self.father.dst_port
        self.ip_src, self.ip_dst=TCP_SEGMENT_SET.find_ip_addr(self.father)
        self.seq_number=self.father.seq_number
        self.ack_number=self.father.ack_number
        
        self.payload=self.father.payload
        self.payload_length=self.father.payload_length
        
        
        if self.src_port in services.sip_ports or self.dst_port in services.sip_ports:
            result=self.decode_sip(self.payload, self.payload_length)
            if result != None:
#                 print result
                self.payload_layer=result
                return self
            else:
                pkt=stream.STREAM(self)
                if pkt.decode(self.payload,self.payload_length) != None:
                    self.payload_layer=pkt
                else:
                    self.payload_layer=None
                return self
            
            
                                
    def __str__(self):
        return "tcp_segment(payload_layer=%s)"%(str_payload_layer(self.payload_layer))

    def to_dict(self):
        d={}
        d['layer_name']=self.layer_name
        d['ip_src']=dec_string(self.ip_src,4,'.') if len(self.ip_src)==4 else hex_string(self.ip_src,16,'')
        d['ip_dst']=dec_string(self.ip_dst,4,'.') if len(self.ip_dst)==4 else hex_string(self.ip_dst,16,'')
        d['src_port']=self.src_port
        d['dst_port']=self.dst_port
        d['seq_number']=self.seq_number
        d['ack_number']=self.ack_number
        d['payload_length']=self.payload_length
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
            
        return d
        
        