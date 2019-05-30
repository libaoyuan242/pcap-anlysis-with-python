# -*- coding:utf-8 -*-

'''
Created on 2016年1月23日

@author: chch
'''
from decode_utils import err, str_to_int, str_to_int_inv
import ether

class pcap_header():
    def __init__(self):
        self.magic=None
        self.major=None
        self.minor=None
        self.timezone=None
        self.sigfigs=None
        self.snaplen=None
        self.linktype=None
    
    def __str__(self):
        return "pcap_header(magic=%s, major=%s, minor=%s, timezone=%s, sigfigs=%s, snaplen=%s, linktype=%s)"%(list(self.magic), self.major, self.minor, self.timezone, self.sigfigs, self.snaplen, self.linktype)
    
    
class pcap_record():
    def __init__(self,father):
        self.father=father
        self.layer_name='enhanced_packet'
        self.ts_sec=None
        self.ts_usec=None
        self.ts_in_second=None
        self.incl_len=None
        self.orig_len=None
        self.packet_data=None
    
    def __str__(self):
        return "enhanced_packet(ts_sec=%s, ts_usec=%s, ts_in_second=%s, incl_len=%s, orig_len=%s, packet_data=%s)"%(self.ts_sec, self.ts_usec, self.ts_in_second, self.incl_len, self.orig_len, list(self.packet_data))
    
    def to_dict(self, pcap_header):
        d={}
        d['layer_name']='enhanced_packet'
        d['ts_sec']=self.ts_sec
        d['ts_usec']=self.ts_usec
        d['ts_in_second']=self.ts_in_second
        d['incl_len']=self.incl_len
        d['orig_len']=self.orig_len
        
        if pcap_header.linktype==1 :
            pkt=ether.ETHER(self)
            if pkt.decode(self.packet_data, self.incl_len)!=None:
                d['payload_layer']=pkt.to_dict()
            else:
                d['payload_layer']=None
        else:
            d['payload_layer']=None
        
        return d


class pcap():
    '''
    pcap decoder
    '''


    def __init__(self, infile):
        '''
        Constructor
        '''
        self.fd=infile
        self.header_already_decoded=None
        self.endianess=None
        
        self.header=None
        
    def __iter__(self):
        while True:
            try:
                yield self.scanner()
            except:
                return
    
    def scanner(self):
        if self.header==None:
            self.header=pcap_header()
            self.header.magic=self.fd.read(4)
            self.header.major=self.fd.read(2)
            self.header.minor=self.fd.read(2)
            self.header.timezone=self.fd.read(4)
            self.header.sigfigs=self.fd.read(4)
            self.header.snaplen=self.fd.read(4)
            self.header.linktype=self.fd.read(4)
            
            if self.header.magic=='\xa1\xb2\xc3\xd4':
                self.endianess=1
            elif self.header.magic=='\xd4\xc3\xb2\xa1':
                self.endianess=-1
            else:
                err('pcap header decode error: unknown endianess: %s'%(self.header))
                return None
            
            self.header.major=str_to_int(self.header.major,2) if self.endianess==1 else str_to_int_inv(self.header.major,2)
            self.header.minor=str_to_int(self.header.minor,2) if self.endianess==1 else str_to_int_inv(self.header.minor,2)
            self.header.timezone=str_to_int(self.header.timezone,2) if self.endianess==1 else str_to_int_inv(self.header.timezone,2)
            self.header.sigfigs=str_to_int(self.header.sigfigs,2) if self.endianess==1 else str_to_int_inv(self.header.sigfigs,2)
            self.header.snaplen=str_to_int(self.header.snaplen,2) if self.endianess==1 else str_to_int_inv(self.header.snaplen,2)
            self.header.linktype=str_to_int(self.header.linktype,2) if self.endianess==1 else str_to_int_inv(self.header.linktype,2)
            
            return self.header
        else:
            pr=pcap_record(None)
            
            buf=self.fd.read(4)
            pr.ts_sec=str_to_int(buf, 4) if self.endianess==1 else str_to_int_inv(buf, 4)
            
            buf=self.fd.read(4)
            pr.ts_usec=str_to_int(buf, 4) if self.endianess==1 else str_to_int_inv(buf, 4)
            
            pr.ts_in_second=pr.ts_sec-self.header.timezone+(pr.ts_usec+0.0)/1000000
            
            buf=self.fd.read(4)
            pr.incl_len=str_to_int(buf, 4) if self.endianess==1 else str_to_int_inv(buf, 4)
            
            buf=self.fd.read(4)
            pr.orig_len=str_to_int(buf, 4) if self.endianess==1 else str_to_int_inv(buf, 4)

            pr.packet_data=self.fd.read(pr.incl_len)
            
            return pr
        
        
        