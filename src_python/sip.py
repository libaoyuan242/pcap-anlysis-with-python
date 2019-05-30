# -*- coding:utf-8 -*-

'''
Created on 2016年1月31日

@author: chch
'''

from bson import Binary
from decode_utils import err

class SIP_REQUEST():
    def __init__(self):
        self.method=None
        self.request_uri=None
        self.version=None
    
    def __str__(self):
        return "sip_request(method=%s, request_uri=%s, version=%s)"%(self.method, self.request_uri, self.version)
    
    def to_dict(self):
        d={}
        d['method']=self.method
        d['request_uri']=self.request_uri
        d['version']=self.version
        return d

class SIP_STATUS():
    def __init__(self):
        self.code=None
        self.code_meaning=None
        self.version=None
    
    def __str__(self):
        return "sip_status(code=%s, code_meaning='%s, version=%s')"%(self.code,self.code_meaning, self.version)

    def to_dict(self):
        d={}
        d['code']=self.code
        d['code_meaning']=self.code_meaning
        d['version']=self.version
        return d

class SIP():
    '''
    classdocs
    '''
    MSG_TYPE_REQUEST=0
    MSG_TYPE_STATUS=1
    REQUEST_TYPES=['INVITE','ACK','BYE','CANCEL','OPTIONS','REGISTER','PRACK','SUBSCRIBE','MESSAGE','NOTIFY','UPDATE','PUBLISH','REFER','INFO']
    seperator="\x0d\x0a"
    
    def __init__(self, father):
        '''
        Constructor
        '''
        self.father=father
        self.layname='sip'
        self.start_line=None
        self.header=None
        self.body=None
        self.complete_flag=None
        self.payload=None
        self.payload_length=None
        self.payload_layer=None
        
    
    def __str__(self):
        return "sip(start_line=%s, header=%s, body=%s)"%(self.start_line, self.header, self.body)
    
    
    def to_dict(self):
        d={}
        d['layer_name']='sip'
#         err(self.start_line)
        d['start_line']=self.start_line.to_dict()
        d['header']=self.header
        
        if ( ('Content-Type' in self.header) and (self.header['Content-Type']=="application/vnd.3gpp.sms")) or (('c' in self.header) and (self.header['c']=="application/vnd.3gpp.sms") ) :
            d['body']=Binary(self.body,5)
        else:
            d['body']=self.body
        
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None
        
        return d


    def decode(self, packet_data, packet_length):
        data=packet_data
        length=packet_length
        
#         err("packet_data length=%s"%(len(data)))
#         err("packet_length=%s"%(length))
        
        
        ### get start_line part
        pos=data.find(SIP.seperator)
        if pos==None:
            return None
        start_line=data[:pos]
        start_line_list=start_line.lstrip(' ').rstrip(' ').split(' ')
        if start_line_list[0] in SIP.REQUEST_TYPES:
            self.start_line=SIP_REQUEST()
            self.start_line.method=start_line_list[0]
            self.start_line.request_uri=start_line_list[1]
            self.start_line.version=start_line_list[2]
        elif start_line_list[0].split('/')[0].upper()=='SIP':
            self.start_line=SIP_STATUS()
            self.start_line.version=start_line_list[0]
            self.start_line.code=start_line_list[1]
            self.start_line.code_meaning=' '.join(start_line_list[2:])
        else:
#             err("unknown sip start line: %s"%(start_line_list))
#             err(1) ## for test
            return None
        data=data[pos+(len(SIP.seperator)):]
        length-=pos+len(SIP.seperator)
        
        ### get header part
        header_flag=1
        header_dict={}
        while(length>0 and header_flag==1):
            pos=data.find(SIP.seperator)
            if pos==0:
                header_flag=0
                self.header=header_dict
            elif pos==None:
                self.start_line=None
                self.header=None
#                 err(2) ## for test
                return None
            else:
                line=data[:pos]
                pos1=line.find(':')
                key=line[:pos1].lstrip(' ').rstrip(' ').replace('.','_')     # to change key string from "P-com.Siemens.Access-Information" to "P-com_Siemens_Access-Information", since '.' is invalid in key string
                value=line[pos1+1:].lstrip(' ').rstrip(' ')
                if key in header_dict:
                    header_dict[key]=header_dict[key]+','+value
                else:
                    header_dict[key]=value
            data=data[pos+len(SIP.seperator):]
            length-=pos+len(SIP.seperator)
        
        if header_flag==1:
            self.start_line=None
            self.header=None
#             err(3) ## for test
            return None
        
        ### get body part
        content_length=None
        if 'Content-Length' in self.header:
            content_length=int(self.header['Content-Length'])
        elif 'l' in self.header:
            content_length=int(self.header['l'])
        else:
#             self.start_line=None
#             self.header=None
#             err(3.1) ## for test
            self.body=None
#             return None
            return self
#         err("content_length=%s,length=%s"%(content_length,length)) ## for test
        if content_length>0:
            if content_length<=length:
                self.body=data[:content_length]
            else:
#                 err(self.start_line) ## for test
#                 err(self.header) ## for test
                self.start_line=None
                self.header=None
                self.body=None
#                 err(4) ## for test
#                 err("content_length=%s,length=%s"%(content_length,length)) ## for test
                return None
        else:
#             err(5) ## for test
            self.body=None
            
#         err(6) ## for test
        return self


    