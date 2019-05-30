# -*- coding:utf-8 -*-

'''
Created on 2016年1月20日

@author: chch
'''
from bson import Binary

class STREAM():
    def __init__(self,father):
        self.father=father
        self.layer_name='stream'
        self.data=None
        self.length=None
        self.payload_layer=None
        self.payload=None
        self.payload_length=None
        
        
    def decode(self,packet_data,length):
        if length<=0:
            return None
        self.data=packet_data
        self.length=length
        self.payload_layer=None
        self.payload=None
        self.payload_length=None
        
        return self
        
    def __str__(self):
        return "stream(length=%s)"%(self.length)
        
    def to_dict(self):
        d={}
        d['layer_name']='stream'
        d['length']=self.length
        d['data']=Binary(self.data,5)
#         d['data']=hex_string(self.data, self.length, ',')
        
        d['payload_layer']=self.payload_layer.to_dict() if self.payload_layer else None

        return d
        
        