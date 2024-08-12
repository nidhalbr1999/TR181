import pytesting as ts
import ast

client = ts.ssh_connection()

'''Interface'''

'''Get '''

#cellular enable
# always enable

#cellular status
def test_cellular_interface_get_status():
    result = ts.test_get_with_ubus(client,"Device.Cellular.Interface",1,"Status","network.device","wwan0","up")
    assert (result['dm_value'] == result['ubus_value'])


#cellular name
def test_cellular_interface_get_name():
    result = ts.test_get_with_uci(client,"Device.Cellular.Interface",1,"Name","network.@device[{}]",None, "name")
    assert result['dm_value'] == result['uci_value']



#cellular enable
#def test_cellular_interface_get_LastChange():


#cellular enable
def test_cellular_interface_get_Upstream():
    result = ts.test_get_with_ubus(client,"Device.Cellular.Interface",1,"Upstream","network.interface{}","interface",None)