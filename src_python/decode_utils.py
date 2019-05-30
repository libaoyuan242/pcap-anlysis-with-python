# -*- coding:utf-8 -*-

'''
Created on 2016年1月19日

@author: chch
'''
import sys

################################################################################
# Auto count class                                                             #
################################################################################
class Counter():
    def __init__(self):
        self.counter=0
    
    def reset(self):
        self.counter=0
    
    def count(self):
        self.counter+=1
        return self.counter
    
    def __str__(self):
        return "%s"%(self.counter)

################################################################################
# print hex digits of an integer                                               #
################################################################################

def hex_digit(digit):
    if (digit>=0) and (digit<10):
        return chr(ord('0')+digit)
    elif (digit>=10) and (digit<16):
        return chr(ord('a')+digit-10)
    else:
        return '?'

################################################################################
# print hex digit of an integer                                                #
################################################################################
def char_hex(char):
    value=ord(char)
    return "%s%s"%(hex_digit(value>>4),hex_digit(value&0x0f))

################################################################################
# print hex digits of byte string with separator                               #
################################################################################
def hex_string(string,length,separator):
    list1=[]
    for i in range(length):
        list1.append(char_hex(string[i]))
    return separator.join(list1)

def dec_string(string,length,separator):
    list1=[]
    for i in range(length):
        list1.append(str(ord(string[i])))
    return separator.join(list1)

def str_to_int(data,length):
    result=0
    for i in range(length):
        result=result*256+ord(data[i])
    return result

def str_to_int_inv(data,length):
    result=0
    for i in range(length):
        result=result*256+ord(data[length-1-i])
    return result

################################################################################
# print information to stdout                                                  #
################################################################################
def info(info_string):
    print info_string

################################################################################
# print information to stderr                                                  #
################################################################################
def err(info_string):
    print >>sys.stderr, info_string

################################################################################
# print object. if the object is None, then print 'nil'                        #
################################################################################
def str_payload_layer(obj):
    if obj!=None:
        return "%s"%(obj)
    else:
        return "nil"


def elt_position(list_of_elt, elt, start=0,key=(lambda x: x),test=(lambda a,b: a==b)):
    for i in range(start,len(list_of_elt)):
        if test(key(list_of_elt[i]),elt):
            return i
    return None

def with_file_ext(filelist,file_ext_list):
    filelist_1=[]
    for fname in filelist:
        for ext in file_ext_list:
            if fname.endswith(ext):
                filelist_1.append(fname)
                break
    return filelist_1

