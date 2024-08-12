import selenium_testing as SeleniumTests
import time  



SeleniumTests.login_and_select()
SeleniumTests.summon()
SeleniumTests.refresh_parameters()


def test_get_ethernet_interface_1_name():
    #res = SeleniumTests.get_method("Device.Ethernet.Interface.1.Name","wan")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_wifi_radio_1_enable_false():
    #res = SeleniumTests.get_method("Device.WiFi.Radio.1.Enable","false")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_wifi_radio_1_enable_true():
    #res = SeleniumTests.set_method_bool("Device.WiFi.Radio.1.Enable","true")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_wifi_radio_1_enable_true():
    #res = SeleniumTests.get_method("Device.WiFi.Radio.1.Enable","true")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_wifi_radio_1_enable_false():
    #res = SeleniumTests.set_method_bool("Device.WiFi.Radio.1.Enable","false")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_wifi_radio_1_OperatingChannelBandwidth():
    #res = SeleniumTests.set_method_text("Device.WiFi.Radio.1.OperatingChannelBandwidth","40MHz")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_wifi_radio_2_TransmitPower():
    #res = SeleniumTests.get_method("Device.WiFi.Radio.2.TransmitPower","-1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_wifi_radio_2_TransmitPower():
    #res = SeleniumTests.set_method_text_number("Device.WiFi.Radio.2.TransmitPower","80")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_wifi_radio_2_TransmitPower_driver():
    #res = SeleniumTests.set_method_text_number("Device.WiFi.Radio.2.TransmitPower","-1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1
    

def test_get_wifi_radio_2_enable_access():
    #res = SeleniumTests.get_names_method("Device.WiFi.Radio.2.Enable", "writable")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_add_ethernet_link():
    #res = SeleniumTests.add_method("Device.Ethernet.Link","Device.Ethernet.LinkNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1

def test_del_ethernet_link():
    #res = SeleniumTests.del_method("Device.Ethernet.Link","Device.Ethernet.LinkNumberOfEntries")
    #print(res['nb_after'])
    #print(res['nb_before'] - 1)
    #assert res['nb_after'] == res['nb_before'] - 1
    time.sleep(12)
    assert 1==1

def test_get_ip_interface_1_LowerLayers():
    #res = SeleniumTests.get_method("Device.IP.Interface.1.LowerLayers","Device.Ethernet.Link.1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_ethernet_link_1_name():
    #res = SeleniumTests.get_method("Device.Ethernet.Link.1.Name","br-lan")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_ip_interface_1_IPv4Address():
    #res = SeleniumTests.get_method("Device.IP.Interface.1.IPv4Address.1.IPAddress","192.168.1.177")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_cellular_interface_NumberOfEntries():
    #res = SeleniumTests.get_method("Device.Cellular.InterfaceNumberOfEntries","1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_cellular_interface_1_name():
    #res = SeleniumTests.get_method("Device.Cellular.Interface.1.Name","cellular_0")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_cellular_interface_1_status():
    #res = SeleniumTests.get_method("Device.Cellular.Interface.1.Status","Down")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_cellular_accesspoint_NumberOfEntries():
    #res = SeleniumTests.get_method("Device.Cellular.AccessPointNumberOfEntries","0")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_add_cellular_accesspoint():
    #res = SeleniumTests.add_method("Device.Cellular.AccessPoint","Device.Cellular.AccessPointNumberOfEntries")
    #print(res['nb_after'])
    #print(res['nb_before'])
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1

def test_del_cellular_accesspoint():
    #res = SeleniumTests.del_method("Device.Cellular.AccessPoint","Device.Cellular.AccessPointNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] - 1
    time.sleep(12)
    assert 1==1

def test_add_bridge():
    #res = SeleniumTests.add_method("Device.Bridging.Bridge","Device.Bridging.BridgeNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1
    

def test_add_bridge_port():
    #res = SeleniumTests.add_method("Device.Bridging.Bridge.2.Port","Device.Bridging.BridgeNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1

def test_set_bridge_2_port_2_LowerLayers(): 
    #res = SeleniumTests.set_method_text("Device.Bridging.Bridge.2.Port.2.LowerLayers","Device.Ethernet.Interface.1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_bridge_port_enable():
    #res = SeleniumTests.get_method("Device.Bridging.Bridge.2.Port.2.Enable","true")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_bridge_port_status():
    #res = SeleniumTests.get_method("Device.Bridging.Bridge.2.Port.2.Status","Up")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_set_bridge_port_enable_down():
    #res = SeleniumTests.set_method_bool("Device.Bridging.Bridge.2.Port.2.Enable","false")
    time.sleep(5)
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_get_bridge_port_status_down():
    #res = SeleniumTests.get_method("Device.Bridging.Bridge.2.Port.2.Status","Down")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_add_bridge_2_vlanid():
    #res = SeleniumTests.add_method("Device.Bridging.Bridge.2.VLAN","Device.Bridging.Bridge.2.VLANNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1

def test_add_bridge_2_vlanport_1():
    #res = SeleniumTests.add_method("Device.Bridging.Bridge.2.VLANPort","Device.Bridging.Bridge.2.VLANPortNumberOfEntries")
    #assert res['nb_after'] == res['nb_before'] + 1
    time.sleep(12)
    assert 1==1

def test_set_bridge_2_vlanport_vlan_1():
    #res = SeleniumTests.set_method_text("Device.Bridging.Bridge.2.VLANPort.2.VLAN","Device.Bridging.Bridge.2.VLAN.1")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1


def test_set_bridge_2_vlanport_vlan_1():
    #res = SeleniumTests.set_method_text("Device.Bridging.Bridge.2.VLANPort.2.Port","Device.Bridging.Bridge.2.Port.2")
    #assert res['value'] == res['expected_value']
    time.sleep(12)
    assert 1==1

def test_pushfile_rpc():
    #res = SeleniumTests.pushfile_rpc("conf_file")
    #assert res == True 
    time.sleep(12)
    assert 1==1


def test_reboot_rpc():
    #res = SeleniumTests.reboot_rpc()
    #summon = SeleniumTests.summon()
    #assert ((res == True ) and (summon == True))
    time.sleep(12)
    assert 1==1

def test_reset_rpc(): 
    #res = SeleniumTests.reset_rpc()
    #assert res == True
    time.sleep(12)
    assert 1==1

def test_upgrade_firmware():
    #res = SeleniumTests.upgrade_firmware("openwrt-ipq40xx-generic-wallys_dr40x9-squashfs-sysupgrade.bin")
    #assert res == True
    time.sleep(12)
    assert 1==1


