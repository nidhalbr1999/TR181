import pytesting as ts
import ast

client = ts.ssh_connection()


'''RADIO'''

'''Get '''
#wifi enable
def test_wifi_get_enable():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"Enable","wireless.radio{}","disabled","Inverted")
    assert result['dm_value'] == result['uci_value']

#wifi status
def test_wifi_get_status():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"Status","network.wireless","radio0","up")
    assert (result['dm_value'] == result['ubus_value'])

#wifi lowerLayer
#test_get_with_uci(client,"Device.WiFi.Radio",1,"LowerLayers",None,None)

#wifi name
def test_wifi_get_name():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"Name","wireless.radio{}",None, "Name")
    assert result['dm_value'] == result['uci_value']

#wifi MaxBitRate
def test_wifi_get_MaxBitRate():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"MaxBitRate","wifi.radio.radio{}".format(0),"maxrate")
    assert (result['dm_value'] == result['ubus_value']) 

#wifi SupportedFrequencyBands
def test_wifi_get_SupportedFrequencyBands():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"SupportedFrequencyBands","wifi.radio.radio{}".format(0),"supp_bands")
    assert (result['dm_value'] == result['ubus_value']) or (result['dm_value'] in result['ubus_value'])

#wifi OperatingFrequencyBand
def test_wifi_get_OperatingFrequencyBand():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",2,"OperatingFrequencyBand","wireless.radio{}","band","Numeric")
    assert result['dm_value'] == result['uci_value']

#wifi SupportedStandards
def test_wifi_get_SupportedStandards():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"SupportedStandards","wifi.radio.radio{}".format(0),"supp_std",None)
    dm_list = result['dm_value'].split(',')
    ubus_list = ast.literal_eval(result['ubus_value'])
    b = True
    for str in ubus_list:
        i = ts.extract_string_from_string(str)
        if i not in dm_list:
            b = False
            break
    assert b == True

#wifi OperatingStandards
def test_wifi_get_OperatingStandards():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"OperatingStandards","wifi.radio.radio{}".format(0),"standard",None)
    ubus_string = result['ubus_value'].replace('802.11', '')
    dm_list = result['dm_value'].split(',')
    ubus_list = ubus_string.split('/')
    b = True
    for str in ubus_list:
        if str not in dm_list:
            b = False
            break
    assert dm_list == ubus_list

#wifi channel
def test_wifi_get_channel():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"Channel","wireless.radio{}","channel")
    assert result['dm_value'] == result['uci_value']

#wifi AutoChannelEnable
def test_wifi_get_AutoChannelEnable():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"AutoChannelEnable","wireless.radio{}","channel","Auto")
    assert result['dm_value'] == result['uci_value']

#wifi OperatingChannelBandwidth
def test_wifi_get_OperatingChannelBandwidth():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"OperatingChannelBandwidth","wireless.radio{}","htmode", "Numeric")
    assert (result['dm_value'] == result['uci_value']) 

#wifi CurrentOperatingChannelBandwidth
def test_wifi_get_CurrentOperatingChannelBandwidth():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"OperatingChannelBandwidth","wireless.radio{}","htmode", "Numeric")
    assert result['dm_value'] == result['uci_value']

#wifi BeaconPeriod
def test_wifi_get_BeaconPeriod():
    result = ts.test_get_with_uci(client,"Device.WiFi.Radio",1,"BeaconPeriod","wireless.radio{}","beacon_int","Inverted")
    if (result['uci_value']== '1'):
        result['uci_value'] = '100'
    assert result['dm_value'] == result['uci_value']

#wifi TransmitPowerSupported


#wifi TransmitPower



#wifi TransmitPower


#wifi Stats
def test_wifi_get_Noise():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"Stats.Noise","wifi.radio.radio{}".format(0),"noise")
    assert (result['dm_value'] == result['ubus_value']) 

def test_wifi_get_BytesSent():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"Stats.BytesSent","wifi.radio.radio{}".format(0),"stats","tx_bytes")
    assert (result['dm_value'] == result['ubus_value'])


'''Set '''

#wifi enable
def test_wifi_set_enable():
    result = ts.test_set_with_uci(client,"Device.WiFi.Radio",1,"Enable","0","wireless.radio{}","disabled","Inverted")
    assert (result['dm_value'] == result['uci_value']) and (result['dm_value'] == result['new_value'])

#wifi channel (corrected)
def test_wifi_set_channel():
    result = ts.test_set_with_uci(client,"Device.WiFi.Radio",1,"Channel","36","wireless.radio{}","channel")
    assert (result['dm_value'] == result['uci_value']) and (result['dm_value'] == result['new_value'])

# wifi OperatingFrequencyBand

#test_set_with_uci(client,"Device.WiFi.Radio",1,"OperatingFrequencyBand","2.4GHz","wireless.radio","band","Numeric")

#wifi AutoChannelEnable
def test_wifi_set_AutoChannelEnable():
    result = ts.test_set_with_uci(client,"Device.WiFi.Radio",1,"AutoChannelEnable","false","wireless.radio{}","channel","Auto")
    assert (result['dm_value'] == result['uci_value']) and (result['dm_value'] == result['new_value'])


#wifi OperatingChannelBandwidth
def test_wifi_set_OperatingChannelBandwidth():
    result = ts.test_set_with_uci(client,"Device.WiFi.Radio",1,"OperatingChannelBandwidth","80MHz","wireless.radio{}","htmode","Numeric")
    dm_value = ts.extract_number_from_string(result['dm_value'])
    uci_value = ts.extract_number_from_string(result['uci_value'])
    new_value = ts.extract_number_from_string(result['new_value'])
    assert (dm_value == uci_value) and (dm_value == new_value)

#wifi BeaconPeriod
def test_wifi_set_BeaconPeriod():
    result = ts.test_set_with_uci(client,"Device.WiFi.Radio",1,"BeaconPeriod","100","wireless.radio{}","beacon_int","Inverted")
    if (result['uci_value']== '1'):
        result['uci_value'] = '100'
    assert (result['dm_value'] == result['uci_value']) and (result['dm_value'] == result['new_value'])

'''ACCESSPOINT'''

'''GET'''
#wifi enable
def test_accesspoint_get_enable():
    result = ts.test_get_with_uci(client,"Device.WiFi.AccessPoint",1,"Enable","wireless.default_radio{}","disabled","Inverted")
    assert (result['dm_value'] == result['uci_value']) 

#wifi status
'''def test_accesspoint_get_staus():
    result = ts.test_get_with_ubus(client,"Device.WiFi.Radio",1,"Status","network.wireless","radio0","up")
    assert (result['dm_value'] == result['ubus_value'])'''


#wifi SSIDReference


#wifi SSIDAdvertisementEnabled
def test_accesspoint_get_SSIDAdvertisementEnabled():
    result = ts.test_get_with_uci(client,"Device.WiFi.AccessPoint",1,"SSIDAdvertisementEnabled","wireless.default_radio{}","hidden","Inverted")
    assert (result['dm_value'] == result['uci_value'])

#wifi WMMEnable
'''def test_accesspoint_get_WMMEnable():
    result = ts.test_get_with_uci(client,"Device.WiFi.AccessPoint",1,"WMMEnable","wireless.default_radio{}","wmm")
    assert (result['dm_value'] == result['uci_value'])'''

#wifi UAPSDEnable
def test_accesspoint_get_UAPSDEnable():
    result = ts.test_get_with_uci(client, "Device.WiFi.AccessPoint", 1, "UAPSDEnable", "wireless.default_radio{}", "wmm_apsd")
    assert (result['dm_value'] == result['uci_value']) 

#wifi AssociatedDeviceNumberOfEntries


#wifi MACAddressControlEnabled
def test_accesspoint_get_MACAddressControlEnabled():
    result = ts.test_get_with_uci(client, "Device.WiFi.AccessPoint", 1, "MACAddressControlEnabled", "wireless.default_radio{}", "macfilter")
    assert (result['dm_value'] == result['uci_value'])

#wifi UAPSDCapability always true


#wifi WMMCapability always true

#wifi MaxAllowedAssociations
def test_accesspoint_get_MaxAllowedAssociations():
    result = ts.test_get_with_uci(client, "Device.WiFi.AccessPoint", 1, "MaxAllowedAssociations", "wireless.default_radio{}", "maxassoc")
    if (result['uci_value'] == '0'):
        result['uci_value'] = result['dm_value']
    assert (result['dm_value'] == result['uci_value'])

#wifi IsolationEnable
def test_accesspoint_get_IsolationEnable():
    result = ts.test_get_with_uci(client, "Device.WiFi.AccessPoint", 1, "IsolationEnable", "wireless.default_radio{}", "isolate")
    assert (result['dm_value'] == result['uci_value'])

#wifi AllowedMACAddress !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
def test_accesspoint_get_AllowedMACAddress():
    result = ts.test_get_with_uci(client, "Device.WiFi.AccessPoint", 1, "AllowedMACAddress", "wireless.default_radio{}", "maclist")
    if (result['dm_value'] == None):
        result['dm_value'] = '0'
    assert (result['dm_value'] == result['uci_value'])

#wifi ModesSupported  !! not working because the wifi.ap.


#wifi Security.ModeEnabled !!!!!!same thing


#wifi Security.WEPKey

