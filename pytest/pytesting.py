import pytest
import paramiko
import re
import json


'''ssh connection'''
def ssh_connection():
    host = "192.168.1.177"
    username = "root"
    password = " "
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    return client

'''execute command'''
def execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    output_string = str(stdout.read().decode())
    if (command.find("bbfdmd -c get") >= 0):
        parameter_value = re.search(r'=>\s*(.*)', output_string)
        value=parameter_value.group(1).strip()
    else:
        value = output_string[:-1]
    
    if (value):
        return value
    else:
        return None

'''extract section_name'''
def extract_name(obj):
    return obj.split('.')[1]

'''extract digit'''
def extract_number_from_string(input_string):
    pattern = r'\d+'
    match = re.search(pattern, input_string)
    
    if match:
        return (match.group())
    else:
        return None
    
'''extract string'''
def extract_string_from_string(input_string):
    return ''.join([char for char in input_string if not char.isdigit()])

    

def auto_option(uci_value):
    if (uci_value == "auto") or (uci_value == ""):
        return '1'
    elif (uci_value.isdigit()):
        return '0'
    if (uci_value == "true"):
        return '1'
    elif (uci_value == "false"):
        return '0'
    
'''values convertion'''
def uci_values_convertion(uci_value,option=None):
    if (uci_value == "auto"):
        uci_value = '1'
    if (option == "Inverted"):
        if (uci_value == None) or (uci_value == '0'):
            uci_value = '1'
        elif (uci_value == '1'):
            uci_value = '0'
    if (uci_value == None) or (uci_value == "disable"):
        uci_value = '0'
    if (uci_value == "allow"):
        uci_value = '1'

    return uci_value


'''compare lists'''
def compare_lists(dm_list, real_list):
    list1 = dm_list.split(",")
    list2 = real_list.split(",")
    if (len(list1) != len(list2)):
        return False
    for real in list2:
        for dm in list1:
            if (dm not in real):
                return False
    return True

def string_to_bool():
    return True

'''get test with uci'''
def test_get_with_uci(client, dm_obj, inst, dm_param, uci_obj, uci_param, Option=None):
    if (inst < 1):
        pytest.skip("Skipping test for radio instance lesser than 1")

    dm_value = execute_command(client, "bbfdmd -c get {obj}.{inst}.{param}".format(obj = dm_obj, inst = inst, param = dm_param))

    if (Option == "Name"):
        obj = uci_obj.format(inst-1)
        name = extract_name(obj)
        result =  dict()
        result['dm_value'] = dm_value
        result['uci_value'] = name
        return result
    
    uci_value = execute_command(client, "uci get " + uci_obj.format(inst-1) + ".{param}".format(param=uci_param))
    
    if (Option == "Numeric"):
        dm_number = extract_number_from_string(dm_value)
        uci_number = extract_number_from_string(uci_value)
        #assert number in uci_value
        result =  dict()
        result['dm_value'] = dm_number
        result['uci_value'] = uci_number
        return result

    if (Option == "Auto"):
        uci_auto = auto_option(uci_value)
        #assert dm_value == auto
        result =  dict()
        result['dm_value'] = dm_value
        result['uci_value'] = uci_auto
        return result
    
    uci_value = uci_values_convertion(uci_value, Option)

    result =  dict()
    result['dm_value'] = dm_value
    result['uci_value'] = uci_value

    return result
    
'''ubus values conversion'''
def ubus_values_convertion(ubus_value):
    if (ubus_value == "True"):
        ubus_value = "Up"
    elif (ubus_value == "False"):
        ubus_value = "Down"

    return ubus_value

'''get test with ubus'''
def test_get_with_ubus(client, dm_obj, inst, dm_param, ubus_obj, json_param1, json_param2 = None):
    if (inst < 1):
        pytest.skip("Skipping test for radio instance lesser than 1")
        
    dm_value = execute_command(client, "bbfdmd -c get {obj}.{inst}.{param}".format(obj = dm_obj, inst = inst, param = dm_param))
    res = execute_command(client, "ubus call {obj} status".format(obj = ubus_obj))
    js = json.loads(res)
    if (json_param2 is None):
        value = str(js[json_param1])
        #assert (dm_value == value) or (dm_value in value) 
        result =  dict()
        result['dm_value'] = dm_value
        result['ubus_value'] = value
        return result
    
    ubus_value = str(js[json_param1][json_param2])

    ubus_value = ubus_values_convertion(ubus_value)

    result =  dict()
    result['dm_value'] = dm_value
    result['ubus_value'] = ubus_value

    return result


'''get test with sysfs'''
def test_get_with_sysfs(client, dm_obj, inst, dm_param, directory, Option=None):
    if (inst < 1):
        pytest.skip("Skipping test for radio instance lesser than 1")

    dm_value = execute_command(client, "bbfdmd -c get {obj}.{inst}.{param}".format(obj = dm_obj, inst = inst, param = dm_param))

    
    #uci_value = execute_command(client, "test -d {dir} && echo 1 || echo 0".format(dir=directory))
    sysfs_value = execute_command(client, "cat {dir} ".format(dir=directory))

    sysfs_value = uci_values_convertion(sysfs_value, Option)

    result =  dict()
    result['dm_value'] = dm_value
    result['sysfs_value'] = sysfs_value

    return result


'''set test with uci'''
def test_set_with_uci(client, dm_obj, inst, dm_param, new_value, uci_obj, uci_param, Option=None):
    if (inst < 1):
        pytest.skip("Skipping test for radio instance lesser than 1")

    execute_command(client, "bbfdmd -c set {obj}.{inst}.{param} {val}".format(obj = dm_obj, inst = inst, param = dm_param, val = new_value))

    dm_value = execute_command(client, "bbfdmd -c get {obj}.{inst}.{param}".format(obj = dm_obj, inst = inst, param = dm_param))

    if (Option == "Name"):
        obj = uci_obj.format(inst-1)
        name = extract_name(obj)
        result =  dict()
        result['dm_value'] = dm_value
        result['uci_value'] = name
        result['new_value'] = new_value
        return result
    
    uci_value = execute_command(client, "uci get " + uci_obj.format(inst-1) + ".{param}".format(param=uci_param))
    
    if (Option == "Numeric"):
        number = extract_number_from_string(dm_value)
        result =  dict()
        result['dm_value'] = number
        result['uci_value'] = uci_value
        result['new_value'] = new_value
        return result

    if (Option == "Auto"):
        uci_auto = auto_option(uci_value)
        dm_auto = auto_option(dm_value)
        new_auto = auto_option(new_value)
        result =  dict()
        result['dm_value'] = dm_auto
        result['uci_value'] = uci_auto
        result['new_value'] = new_auto
        return result
    
    uci_value = uci_values_convertion(uci_value, Option)

    result =  dict()
    result['dm_value'] = dm_value
    result['uci_value'] = uci_value
    result['new_value'] = new_value

    return result
    


'''set test with ubus'''
def test_set_with_ubus(client, dm_obj, inst, dm_param, new_value, ubus_obj, json_param1, json_param2):
    if (inst < 1):
        pytest.skip("Skipping test for radio instance lesser than 1")

    execute_command(client, "bbfdmd -c set {obj}.{inst}.{param} {val}".format(obj = dm_obj, inst = inst, param = dm_param, val = new_value))

'''move dmmap file to config'''
def import_dmmap_file(client, dmmap_file):

    execute_command(client, "mv /etc/bbfdm/dmmap/{dmmap} /etc/config/".format(dmmap = dmmap_file))

def delete_dmmap_file(client, dmmap_file):

    execute_command(client, "rm /etc/config/{dmmap} ".format(dmmap = dmmap_file))

def get_LowerLayers(client, dm_obj, inst):
    Upperlayer_name = execute_command(client, "bbfdmd -c get {obj}.{inst}.Name".format(obj = dm_obj, inst = inst))
    lowerlayer = execute_command(client, "bbfdmd -c get {obj}.{inst}.LowerLayers".format(obj = dm_obj, inst = inst))
    Lowerlayer_name = execute_command(client, "bbfdmd -c get {object}.Name".format(object = lowerlayer))
    result =  dict()
    result['Upperlayer_name'] = Upperlayer_name
    result['Lowerlayer_name'] = Lowerlayer_name
    return result
    




    

    