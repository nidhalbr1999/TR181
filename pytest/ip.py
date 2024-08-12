import pytesting as ts


client = ts.ssh_connection()

'''Get'''

def test_bridge_get_enable():
    result = ts.test_get_with_ubus(client,"Device.Cellular.Interface",1,"Status","network.device","wwan0","up")
    assert result == True