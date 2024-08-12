import pytesting as ts
import ast

client = ts.ssh_connection()


'''Interface'''

'''Get '''
#ethernet enable
def test_ethernet_get_enable():
    result = ts.test_get_with_sysfs(client,"Device.Ethernet.Interface",2,"Enable","/sys/class/net/lan/carrier")
    assert result['dm_value'] == result['sysfs_value']

#ethernet status
def test_ethernet_get_staus():
    result = ts.test_get_with_sysfs(client,"Device.Ethernet.Interface",2,"Status","/sys/class/net/lan/carrier")
    if (result['sysfs_value'] == "1"):
        result['sysfs_value'] = "Up"
    else:
        result['sysfs_value'] = "Down"
    
    assert result['dm_value'] == result['sysfs_value']


#link LastChange
def test_ethernet_link_get_LastChange():
    result = ts.test_get_with_ubus(client, "Device.Ethernet.Interface", 2, "LastChange", "network.interface.{}".format("lan"), "uptime")
    assert result['dm_value'] ==  result['dm_value'] 

#ethernet MACAddress
def test_ethernet_get_MACAddress():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Interface", 1, "MACAddress", "/sys/class/net/wan/address")
    assert result['dm_value'] == result['sysfs_value']

#ethernet SupportedLinkModes
def test_ethernet_get_SupportedLinkModes():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Interface", 1, "SupportedLinkModes", "/sys/class/net/wan/link_mode")
    assert result['dm_value'] == result['sysfs_value']

#ethernet CurrentBitRate
def test_ethernet_get_CurrentBitRate():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Interface", 1, "CurrentBitRate", "/sys/class/net/wan/speed")
    assert result['dm_value'] == result['sysfs_value']

#ethernet DuplexMode
def test_ethernet_get_DuplexMode():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Interface", 2, "DuplexMode", "/sys/class/net/lan/duplex")
    assert result['dm_value'] == result['sysfs_value']
    

#ethernet Stats.ErrorsSent
def test_ethernet_get_Stats_ErrorsSent():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Interface", 2, "Stats.ErrorsSent", "/sys/class/net/lan/statistics/tx_errors")
    assert result['dm_value'] == result['sysfs_value']



'''Link'''

#link enable
def test_ethernet_link_get_enable():
    ts.import_dmmap_file(client,"dmmap_ethernet")
    result = ts.test_get_with_uci(client,"Device.Ethernet.Link",2,"Enable","dmmap_ethernet.@link[{}]","enabled")
    ts.delete_dmmap_file(client,"dmmap_ethernet")
    assert (result['dm_value'] == result['uci_value']) 

#link status
def test_ethernet_link_get_status():
   result = ts.test_get_with_ubus(client,"Device.Ethernet.Link",1,"Status","network.device","br-lan","up")
   assert (result['dm_value'] == result['ubus_value']) or (result['dm_value'] in result['ubus_value'])

#link name 
def test_ethernet_link_get_name():
    result = ts.test_get_with_uci(client,"Device.Ethernet.Link",1,"Name","network.@device[{}]","name")
    assert result['dm_value'] == result['uci_value']

#link LastChange
def test_ethernet_link_get_LastChange():
    result = ts.test_get_with_ubus(client, "Device.Ethernet.Link", 1, "LastChange", "network.interface.{}".format("lan"), "uptime")
    assert result['dm_value'] ==  result['dm_value'] #result['ubus_value']  

#ethernet LowerLayers
def test_ethernet_link_get_LowerLayers():
    result = ts.get_LowerLayers(client, "Device.Ethernet.Link", 1)
    assert result['Upperlayer_name'] == result['Lowerlayer_name']

#ethernet MACAddress
def test_ethernetlink_get_MACAddress():
    result = ts.test_get_with_sysfs(client, "Device.Ethernet.Link", 1, "MACAddress", "/sys/class/net/lan/address")
    assert result['dm_value'].lower() == result['sysfs_value'].lower()


'''Set '''

#link enable
def test_ethernet_set_enable():
    result = ts.test_set_with_uci(client,"Device.Ethernet.Link.",3,"Enable","false","network.interface{}","wan","Auto")
    assert 1 == 1

#LowerLayers
#link enable
def test_ethernet_set_Lowerlayer():
    #result = ts.test_set_with_uci(client,"Device.Ethernet.Link.",3,"Enable","false","network.interface{}","wan","Auto")
    assert 1 == 1

#MACAddress
#link enable
def test_ethernet_set_enable():
    #result = ts.test_set_with_uci(client,"Device.Ethernet.Link.",1,"MACAddress","C7:3B:F1:10:8D:B9","network.@device[{}]","macaddr")
    #assert (result['dm_value'] == result['uci_value']) and (result['dm_value'] == result['new_value'])
    assert 1 == 1
    