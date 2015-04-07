'''
Created on 25.03.2015

@author: Hakan Calim<Hakan.Calim@fau.de>
'''

'''
Module for converting bwctl limits format file into v2 format
'''

import re
import sys

default_limits_file_name = "bwctld.v2.limits"

def get_limits_asstring(limits_file=None):
    '''
    Open a limits file and return it as string
    '''
    limits_as_string = None
    try:
        limit_file_object = open(limits_file, 'r')
        limits_as_string = limit_file_object.read()
        #Remove double quotes code from unicode
        limits_as_string = re.sub('\xe2\x80\x9d','"',limits_as_string)
        limits_as_string = re.sub('\xe2\x80\x9c','"',limits_as_string)
        limit_file_object.close()
    except IOError as e:
        raise Exception( "Cannot open limits file: " + limits_file)
    return limits_as_string

def write_to_file(limits_as_v2_string=""):
    try:
        limits_v2_file_object = open(default_limits_file_name, 'w')
        limits_v2_file_object.write(limits_as_v2_string)
        limits_v2_file_object.close()
    except IOError as e:
        raise Exception("Cannot create new v2 limits file.")
              
        

def parse(limits_file_path=None, output="file"):
    '''
    Here starts the parsing of limits file.
    parse(limits_file_path=None)
    limits_file_path :Path to the limits file v1 format.
    '''
    if len(sys.argv) > 1:
        print "Start converting limits file to v2..."
        limits_file_path = sys.argv[1]
    limit_classes = {}
    limits_v1_as_string = get_limits_asstring(limits_file_path)
    parse_limits(limit_classes, limits_v1_as_string)
    parse_assign(limit_classes, limits_v1_as_string)
        
    if "dict".__eq__(output):
        return limit_classes
    else:
        write_to_file(get_v2_as_string(limit_classes))
        print "Done.\n"
    
    
def parse_limits(limit_classes, limits_v1_as_string=""):
    pattern_get_limits = '^limit \w+ with.*\n(?:\s+\w+.*\n){0,}'
    limits = re.findall(pattern_get_limits, limits_v1_as_string, re.M)
    if len(limits) < 1:
        raise Exception("No Limits defined in format 1.x ")
    
    for limit in limits:
        new_limit = re.sub(r'\\\n','',limit,re.M)
        new_limit = re.sub(r'\n','',new_limit,re.M)
        m = re.search(r'limit (\w+) with\s+(\w+=\w+),',new_limit)
        if m:
            new_limit = re.sub(r'\s+','',new_limit)
            limit_types = new_limit.split(',')
            del limit_types[0]  #elete head with limit class_name with..
            limit_types.append(m.group(2)) #append parameter which is in head
            limit_classes[m.group(1)] = {"LIMITTYPES" : limit_types}
            limit_classes[m.group(1)]["PARENT"] =  class_has_parent(limit_types, limit_classes)
            limit_classes[m.group(1)]["ASSIGN"] = {}
    #print limit_classes

            
def parse_assign(limit_classes, limits_v1_as_string=""):
    pattern_get_assigns = 'assign.*\n'
    #limits_v1_as_string = re.sub('assign net','assign network',limits_v1_as_string)
    assigns = re.findall(pattern_get_assigns, limits_v1_as_string)
    for assign in assigns:
        match = re.search(r'assign\s+(\w+)\s+(\S+)\s*(\S*)\s*', assign, re.DOTALL)            
        if match:
            elements = match.groups()
            parent = elements[2] if elements[2] != '' else elements[1]
            assign_type = elements[0]
            assign_value = elements[1] if elements[2] != '' else ""
            parent = parent.replace('"', '')
            if parent in limit_classes: #found class
                if not assign_type in limit_classes[parent]['ASSIGN']: # check if assign type exist
                    limit_classes[parent]['ASSIGN'] = { assign_type : [assign_value] } # Make new  assign entry
                else:
                    limit_classes[parent]['ASSIGN'][assign_type].append(assign_value)
            else:
                raise Exception("Parent class name: %s not exist. Please check your limits file." % parent)
    
             
                   
limit_types_syntax = { "allow_open_mode" : ["on","off"],
                      "allow_tcp": ["on","off"],
                      "allow_udp": ["on","off"],
                      "bandwidth": ["int"],
                      "duration": ["int"],
                      "event_horizon" : ["int"],
                      "max_time_error" : ["int"],
                      "pending" : ["int"],
                      "parent" : ["string"],
                      }


def limit_types_syntax_check(limit_type):
    '''
    Checks if types are correct in limits file.
    '''
    match = re.search(r'(\w+)=(\w+)', limit_type)
    if match:
        if not match.group(1) in limit_types_syntax:
            print "OHoh"
            raise Exception("This limit type: %s is not alloed" % match.group(1))
        elif not check_limit_type_value(match.group(1), match.group(2)):
            raise Exception("Syntax check of limit type: %s fails" % limit_type)
                   
            
def check_limit_type_value(limit_type, limit_type_value):
    retval = None
    value = limit_types_syntax[limit_type]
    if "string" in value:
        if type(limit_type_value) == type(""):
            retval = 1
    elif "int" in value:
        # We can have values 50m
        #AB: this doesn't seem to handle the "50m" case noted above
        match =  re.search(r'(\d+)\S*', limit_type_value)
        if type(int(match.group(1))) == type(1):
            retval = 1
    else:
        if limit_type_value in value:
            retval = 1                
    return retval            
            
def class_has_parent(limit_types, limit_classes):
    for limit_type in limit_types:
        #check first if limit_type is correct syntax
        limit_types_syntax_check(limit_type)
        match =  re.search(r'parent=(\w+)', limit_type)
        if match:
            #Syntax check if aprent exist
            if match.group(1) in limit_classes:
                return match.group(1) #parent class name
            else:
                raise Exception('Class name: %s does not exist! Please define it parent first.' % match.group(1))

def get_v2_as_string(limits_classes):
    v2_as_string = ""
    assigns_as_string = ""
    for class_name in reversed(limits_classes.keys()):
        parent = limits_classes[class_name]['PARENT']
        assigns = limits_classes[class_name]['ASSIGN']
        assigns_as_string = assigns_as_string + get_assigns_as_string(assigns, class_name)
        limit_types = limits_classes[class_name]['LIMITTYPES']
        #remove parent 
        filtered_limits_types = [ v for v in limit_types if not v.startswith('parent') and not v.startswith("max_time_error") ]

        class_name = '"%s"' % class_name
        v2_as_string = v2_as_string +"<class %s>\n" % class_name
        if parent:
            parent = '"%s"' % parent
            v2_as_string =  v2_as_string + "\tparent\t%s\n" % parent
        v2_as_string = v2_as_string + "\t<default_limits>\n\t\t%s\n\t</default_limits>\n</class>\n" % "\n\t\t".join(filtered_limits_types)
    v2_as_string = v2_as_string + assigns_as_string
    return  v2_as_string     

def get_assigns_as_string(assigns, parent):
    assigns_as_string = ""
    assign_type_as_string = ""
    for assgin_type in assigns:
        if "net".__eq__(assgin_type):
            assign_type_as_string = "network"
        else:
            assign_type_as_string = assgin_type
        for assing_value in assigns[assgin_type]:
            assign_str = 'assign %s %s "%s" \n' % (assign_type_as_string, assing_value, parent)
            assigns_as_string = assigns_as_string + assign_str
    return assigns_as_string
        
    
             

#################################
# Helful methods for testing ####
#################################
#AB: is there a reason to return a number instead of just returning the
# limits themselves, and having the caller do "len"?
def get_num_of_limit_assigns(limit_classes,  class_name):
    return len(limit_classes[class_name]['ASSIGN']['net']) # at the moment it returns only net entries
def get_class_parent(limit_classes, class_name=None):
    if class_name:
        return limit_classes[class_name]["PARENT"]
    else:
        raise Exception('Please define a limit class name!')        
def get_num_of_limit_types(limit_classes, class_name=None):
    if class_name:
        return len(limit_classes[class_name]["LIMITTYPES"])
    else:
        raise Exception('Please define a limit class name!')

if __name__ == '__main__':
    pass