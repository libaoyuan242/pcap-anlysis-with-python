# -*- coding:utf-8 -*-

'''
Created on 2016年1月28日

@author: chch
'''

from decode_utils import err, str_to_int, str_to_int_inv, hex_string
import ether


class option():
    def __init__(self):
        self.code=None
        self.length=None
        self.value=None

class block():
    def __init__(self):
        self.type=None
        self.total_length=None
        self.body=None
        self.total_length_end=None
        self.options=None
    
    def __str__(self):
        return "pcapng_block(type=(%s), total_length=%s)"%(self.type, self.total_length)
    
class section_header_block(block):
    def __init__(self):
        self.type=None
        self.total_length=None
        self.byte_order_magic=None
        self.major=None
        self.minor=None
        self.section_length=None
        self.options=None
        self.total_length_end=None
        
    def __str__(self):
        return "section_header_block(type=(%s), total_length=%s)"%(hex_string(self.type,4,','), self.total_length)
    
class  interface_description_block(block):
    def __init__(self):
        self.type=None
        self.total_length=None
        self.link_type=None
        self.snap_len=None
        self.options=None
        self.total_length_end=None
        
    def __str__(self):
        return "interface_description_block(type=(%s), total_length=%s, link_type=%s, snap_len=%s)"%(self.type, self.total_length, self.link_type, self.snap_len)
         
        
class enhanced_packet_block(block):
    def __init__(self,father):
        self.father=father
        self.layer_name='enhanced_packet'
        self.type=None
        self.total_length=None
        self.interface_id=None
        self.timestamp_high=None
        self.timestamp_low=None
        self.captured_len=None
        self.packet_len=None
        self.packet_data=None
        self.options=None
        self.total_length_end=None
        self.ts_in_second=None ## calculated
        
    def __str__(self):
        return "enhanced_packet_block(type=(%s), total_length=%s, interface_id=%s, ts_in_second=%s, captured_len=%s, packet_len=%s)"%(self.type, self.total_length, self.interface_id, self.ts_in_second, self.captured_len, self.packet_len)
        
    def to_dict(self, interface_description_block):
        d={}
        d['layer_name']=self.layer_name
        d['ts_sec']=self.timestamp_high
        d['ts_usec']=self.timestamp_low
        d['ts_in_second']=self.ts_in_second
        d['incl_len']=self.captured_len
        d['orig_len']=self.packet_len
        
        if interface_description_block.link_type==1 :
            pkt=ether.ETHER(self)
            if pkt.decode(self.packet_data, self.captured_len)!=None:
                d['payload_layer']=pkt.to_dict()
            else:
                d['payload_layer']=None
        else:
            d['payload_layer']=None
        
        return d

        
class simple_packet_block(block):
    def __init__(self):
        self.type=None
        self.total_length=None
        self.packet_len=None
        self.packet_data=None
        self.total_length_end=None
        
    def __str__(self):
        return "simple_packet_block(type=(%s), total_length=%s, packet_len=%s)"%(self.type, self.total_length, self.packet_len)
        
    
class name_resolution_record(block):
    def __init__(self):
        self.type=None
        self.length=None
        self.value=None

    def __str__(self):
        return "name_resolution_record(type=(%s), length=%s, value=%s)"%(self.type, self.length, self.value)
    
    
    
class name_resolution_block(block):
    def __init__(self):
        self.type=None
        self.total_length=None
        self.records=None
        self.options=None
        self.total_length_end=None
        
    def __str__(self):
        return "name_resolution_block(type=(%s), total_length=%s, packet_len=%s)"%(self.type, self.total_length, self.packet_len)
        
class interface_statistics_block(block):
    def __init__(self):
        self.type=None
        self.total_length=None
        self.interface_id=None
        self.timestamp_high=None
        self.timestamp_low=None
        self.options=None
        self.total_length_end=None
        self.ts_in_second=None
        
    def __str__(self):
        return "interface_statistics_block(type=(%s), total_length=%s, interface_id=%s, ts_in_second=%s)"%(self.type, self.total_length, self.interface_id, self.ts_in_second)
    

class pcapng():
    '''
    pcapng decoder
    '''


    def __init__(self, infile):
        '''
        Constructor
        '''
        self.fd=infile
        self.header_already_decoded=None
        self.endianess=1
        
        self.header=None
        
    def __iter__(self):
        while True:
            try:
                yield self.scanner()
            except:
                return


    def decode_uint16(self,str_buf):
        return str_to_int(str_buf, 2) if self.endianess>0 else str_to_int_inv(str_buf,2)

    def decode_uint32(self,str_buf):
        return str_to_int(str_buf, 4) if self.endianess>0 else str_to_int_inv(str_buf,4)
    
    def decode_uint64(self,str_buf):
        return str_to_int(str_buf, 8) if self.endianess>0 else str_to_int_inv(str_buf,8)
    
    def scanner(self):
        buf_type=self.fd.read(4)
        buf_length=self.fd.read(4)
        if self.decode_uint32(buf_type)==0x0a0d0d0a:
            buf_byte_order_magic=self.fd.read(4)
            if buf_byte_order_magic=='\x1A\x2B\x3C\x4D':
                self.endianess=1
            elif buf_byte_order_magic=='\x4D\x3C\x2B\x1A':
                self.endianess=-1
            else:
                err("error examining byte order magic: (%s)"%(hex_string(buf_byte_order_magic, 4, ',')))
                return
            block=section_header_block()
            block.type=buf_type
            block.total_length=self.decode_uint32(buf_length)
            buf=self.fd.read(block.total_length-12)
            block.major=self.decode_uint16(buf[:2])
            block.manor=self.decode_uint16(buf[2:4])
            block.options=buf[4:-4]
            block.total_length_end=self.decode_uint32(buf[-4:])
            return block
        
        elif self.decode_uint32(buf_type)==1:
            block=interface_description_block()
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            block.link_type=self.decode_uint16(self.fd.read(2))
            block.snap_len=self.decode_uint16(self.fd.read(2))
            block.options=self.fd.read(block.total_length-16)
            block.total_length_end=self.decode_uint32(self.fd.read(4))
            return block
        
        elif self.decode_uint32(buf_type)==6:
#             err("this is an enhanced_packet_block")
            block=enhanced_packet_block(None)
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            block.interface_id=self.decode_uint32(self.fd.read(4))
            block.timestamp_high=self.decode_uint32(self.fd.read(4))
            block.timestamp_low=self.decode_uint32(self.fd.read(4))
            block.captured_len=self.decode_uint32(self.fd.read(4))
#             err(111)
            block.packet_len=self.decode_uint32(self.fd.read(4))
#             err(222)
#             block.packet_data=self.fd.read((block.captured_len+3)/4*4)[:block.captured_len]
#             err("cap_len=%s, packet_len=%s"%(block.captured_len, block.packet_len))
            block.packet_data=self.fd.read((block.captured_len+3)/4*4)
#             err(333)
            block.packet_data=block.packet_data[:block.captured_len]
#             err(444)
            block.options=self.fd.read(block.total_length-32-(block.captured_len+3)/4*4)
#             err(555)
            block.total_length_end=self.decode_uint32(self.fd.read(4))
#             err(666)
            block.ts_in_second=((block.timestamp_high<<32)+block.timestamp_low+0.0)/1000000
#             err(777)
#             err("epb:%s"%(block))
            return block

# class simple_packet_block(block):
#     def __init__(self):
#         self.type=None
#         self.total_length=None
#         self.packet_len=None
#         self.packet_data=None
#         self.total_length_end=None
#         
#     def __str__(self):
#         return "simple_packet_block(type=(%s), total_length=%s, packet_len=%s)"%(hex_string(self.type,4,','), self.total_length, self.packet_len)
#         
        
        elif self.decode_uint32(buf_type)==3:
            block=simple_packet_block()
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            block.packet_len=self.decode_uint32(self.fd.read(4))
            block.packet_data=self.fd.read((block.packet_len+3)/4*4)[:block.packet_len]
            block.total_length_end=self.decode_uint32(self.fd.read(4))
            return block
# class name_resolution_block(block):
#     def __init__(self):
#         self.type=None
#         self.total_length=None
#         self.records=None
#         self.options=None
#         self.total_length_end=None
#         
#     def __str__(self):
#         return "name_resolution_block(type=(%s), total_length=%s, packet_len=%s)"%(hex_string(self.type,4,','), self.total_length, self.packet_len)
#         
        elif self.decode_uint32(buf_type)==4:
            block=name_resolution_block()
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            self.fd.read(block.total_length-12)
            block.total_length_end=self.decode_uint32(self.fd.read(4))
            return block

# class interface_statistics_block(block):
#     def __init__(self):
#         self.type=None
#         self.total_length=None
#         self.interface_id=None
#         self.timestamp_high=None
#         self.timestamp_low=None
#         self.options=None
#         self.total_length_end=None
#         self.ts_in_second=None
#         
#     def __str__(self):
#         return "interface_statistics_block(type=(%s), total_length=%s, interface_id=%s, ts_in_second=%s)"%(hex_string(self.type,4,','), self.total_length, self.interface_id, self.ts_in_second)
        
        
        elif self.decode_uint32(buf_type)==5:
            block=interface_statistics_block()
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            block.interface_id=self.decode_uint32(self.fd.read(4))
            block.timestamp_high=self.decode_uint32(self.fd.read(4))
            block.timestamp_low=self.decode_uint32(self.fd.read(4))
            block.options=self.fd.read(block.total_length-24)
            block.total_length_end=self.decode_uint32(self.fd.read(4))
            block.ts_in_second=(block.timestamp_high<<32+block.timestamp_low)/1000000.0
            return block
        else:
            block=block()
            block.type=self.decode_uint32(buf_type)
            block.total_length=self.decode_uint32(buf_length)
            block.body=self.fd.read(block.total_length-12)
            block.total_length_end=self.decode_uint32(self.fd.read(4))
            return block
        
        