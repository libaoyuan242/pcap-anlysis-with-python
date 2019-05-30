# -*- coding:utf-8 -*-

'''
Created on 2016年1月25日

@author: chch
'''

import ip
import ipv6_fragment
from decode_utils import err

class IP_FRAGMENT_SET(object):
    '''
    classdocs
    '''
    set={}
    timeout=3


    def __init__(self, params):
        '''
        Constructor
        '''
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
        else:
            return "%s.%s"%(cls.make_protocol_stack_key(obj.father),cls.make_protocol_layer_name(obj))
    @classmethod
    def make_ip_fragment_info_key(cls,obj):
        if isinstance(obj, ipv6_fragment.IPV6_FRAGMENT):
            return "src=%s,id=%s"%(obj.father.src, obj.identification)
        if isinstance(obj, ip.IPV4):
            return "src=%s,id=%s"%(obj.src, obj.id)
    
    @classmethod
    def make_fragment_set_key(cls,obj):
        return "((%s),(%s))"%(cls.make_protocol_stack_key(obj),cls.make_ip_fragment_info_key(obj))

    @classmethod
    def is_in_fragment_set(cls,obj):
        '''
        return if this fragment is in the fragment set
        '''
        key_string=cls.make_fragment_set_key(obj)
        return True if key_string in cls.set else None
    
    @classmethod
    def sort_frags_by_offset(cls,frag_list):
        if isinstance(frag_list[0],ipv6_fragment.IPV6_FRAGMENT):
            return sorted(frag_list, key=lambda frag: frag.offset)
        elif isinstance(frag_list[0], ip.IPV4):
            return sorted(frag_list, key=lambda frag: frag.fragment_offset)
        else:
            err("unknown fragment type in sort_frags_by_offset")
    
    @classmethod
    def has_all_frags(cls,frag_list):
        sorted_frag_list=cls.sort_frags_by_offset(frag_list)
        n_offset=0
        for item in sorted_frag_list:
            if isinstance(item, ipv6_fragment.IPV6_FRAGMENT):
                if (item.offset*8)==n_offset:
                    n_offset+=item.payload_length
                else:
                    return False
            else:
                if (item.fragment_offset*8)==n_offset:
                    n_offset+=item.payload_length
                else:
                    return False
        if sorted_frag_list[len(sorted_frag_list)-1].more_fragments==0:
            return True
        else:
            return False
        
    @classmethod
    def equal(cls,frag1,frag2):
        if isinstance(frag1,ipv6_fragment.IPV6_FRAGMENT) and isinstance(frag2,ipv6_fragment.IPV6_FRAGMENT):
            return frag1.next_header==frag2.next_header and frag1.offset==frag2.offset and frag1.more_fragments==frag2.more_fragments
        elif isinstance(frag1,ip.IPV4) and isinstance(frag2,ip.IPV4):
            return frag1.protocol==frag2.protocol and frag1.fragment_offset==frag2.fragment_offset and frag1.more_fragments==frag2.more_fragments
        else:
            err("error evaluate equal of fragment-1 and fragment-2")
            return False
    
    @classmethod
    def combine(cls,obj):
        cls.remove_timeout_fragments_from_fragment_set(obj)
        
        key_string=cls.make_fragment_set_key(obj)
        
        if cls.is_in_fragment_set(obj)==None:
            cls.set[key_string]=[obj]
            return None
        else:
            frag_list=cls.set[key_string]
            for item in frag_list:
                if cls.equal(item,obj):
                    return None
            frag_list.append(obj)
            if cls.has_all_frags(frag_list):
                del cls.set[key_string]
                return cls.combine_fragments(frag_list)
            else:
                cls.set[key_string]=frag_list
                return None
    
    @classmethod
    def combine_fragments(cls,fragment_list):
        '''
        combine the payload data for all fragments according to the order of offset, and return the combined payload data and payload_length.
        '''
        list1=cls.sort_frags_by_offset(fragment_list)
        length=0
        buf=''
        for item in list1:
            length+=item.payload_length
            buf=buf+item.payload
        return (buf,length)
    
    @classmethod
    def get_timestamp(cls,obj):
        if obj==None:
            return None
        elif obj.layer_name=='enhanced_packet':
            return obj.ts_in_second
        else:
            return cls.get_timestamp(obj.father)
        
    @classmethod
    def remove_timeout_fragments_from_fragment_set(cls,obj):
        '''
        remove all time out fragments from the fragment set. a time out packet is the one whose captured time is "self.timeout" seconds earlier than the timestamp of current fragment(self).
        '''
        current_ts=cls.get_timestamp(obj)
        if current_ts==None:
            return
        new_set={}
        
        for key in cls.set:
            frag_list=cls.set[key]
            item_list=[]
            for item in frag_list:
                item_ts=cls.get_timestamp(item)
                if item_ts!=None and item_ts>=(current_ts-cls.timeout):
                    item_list.append(item)
            if len(item_list)>0:
                new_set[key]=item_list
        
        cls.set=new_set
        return



