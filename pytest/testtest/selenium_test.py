from selenium import webdriver  
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time  
import re  
from colorama import Fore, Style, init
import inspect
import paramiko

nb_passed = 0
nb_failed = 0
list_of_functions = []

driver = webdriver.Edge() 
driver.maximize_window()  
driver.get("http://localhost:3000/")  

###SSH Connection###
def ssh_connection():
    host = "192.168.1.177"
    username = "root"
    password = " "
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    return client

###Login###
def login_and_select():
    driver.find_element(By.NAME, 'username').send_keys("admin")
    driver.find_element(By.NAME, 'password').send_keys("admin")
    time.sleep(1.5)
    ###Login button###
    driver.find_element(By.CSS_SELECTOR, 'button[type="submit"].primary').click()
    time.sleep(1.5) # Wait for the page to load
    ###Devices button###
    driver.find_element(By.LINK_TEXT, 'Devices').click()
    time.sleep(1.5)
    ###Select Luceor###
    tr_element = driver.find_element(By.XPATH, '//tr[td/span[@class="parameter-value"]/span[@class="long-text" and text()="Luceor"]]')
    tr_element.find_element(By.PARTIAL_LINK_TEXT, 'Show').click()
    time.sleep(1.5)

###Summon###
def summon():
    driver.find_element(By.XPATH, '//button[@title="Initiate session and refresh basic parameters"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Summoned'))
    time.sleep(1.5)


###Reboot###
def reboot_rpc():
    driver.find_element(By.XPATH, '//button[@title="Reboot device" and @class="primary"]').click()
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Initiate session and refresh basic parameters"]').click()
    if (WebDriverWait(driver, 20).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: No contact from CPE'))):
        reboot = True
    else:
        reboot = False
    time.sleep(1.5)
    try:
        assert (reboot == True)
        global nb_passed
        nb_passed += 1
        
        list_of_functions.append((get_function_name(),1))
        time.sleep(50)
    except:
        expect_return(reboot, True)
        global nb_failed
        nb_failed += 1
        list_of_functions.append((get_function_name(),-1))
    return 

###Reset###
def reset_rpc():
    driver.find_element(By.XPATH, '//button[@title="Factory reset device" and @class="critical"]').click()
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Initiate session and refresh basic parameters"]').click()
    if (WebDriverWait(driver, 20).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: No contact from CPE'))):
        reset = True
    else:
        reset = False
    time.sleep(1.5)
    try:
        assert (reset == True)
        global nb_passed
        nb_passed += 1
        
        list_of_functions.append((get_function_name(),1))
        time.sleep(50)
    except:
        expect_return(reset, True)
        global nb_failed
        nb_failed += 1
        list_of_functions.append((get_function_name(),-1))
    return 

###Push file###
def pushfile_rpc(filename):
    driver.find_element(By.XPATH, '//button[@title="Push a firmware or a config file" and @class="critical"]').click()
    time.sleep(2)
    xpath = f"//select/option[text()='{filename}']"
    driver.find_element(By.XPATH, xpath).click()
    time.sleep(1)
    driver.find_element(By.XPATH, '//button[@title="Queue task" and @class="primary"]').click()
    time.sleep(1)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(1.5)
    client = ssh_connection()
    stdin, stdout, stderr = client.exec_command("find /tmp -name {}".format(filename))
    output_string = str(stdout.read().decode())
    if (output_string != ""):
        res = True
    else:
        res = False
    try:
        assert (res == True)
        global nb_passed
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(f"/tmp/{filename}", output_string)
        global nb_failed
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return 

###Upgrade###
def upgrade_firmware(filename):
    pushfile_rpc(filename)
    time.sleep(60)


###Refresh###
def refresh_parameters():
    m_element = driver.find_element(By.XPATH, '//m')
    numbers = re.findall(r'\d+', m_element.text)
    if (numbers[0] == numbers[1]):
        tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@title="Device" and @class="long-text"] and td[@class="right"]/button[@title="Refresh tree"]]')
        tr_element.find_element(By.XPATH, './/button[@title="Refresh tree"]').click()
        driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
        WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))

def get_function_name():
    current_frame = inspect.currentframe()
    caller_frame = current_frame.f_back
    current_function = caller_frame.f_code.co_name

    args, _, _, values = inspect.getargvalues(caller_frame)
    args_info = ", ".join(f"{arg}={values[arg]!r}" for arg in args)

    name = f"{current_function}({args_info})"
    return name


def expect_return(value,expected_value):
    current_frame = inspect.currentframe()
    caller_frame = current_frame.f_back
    script_name = caller_frame.f_code.co_filename
    line_number = caller_frame.f_lineno
    current_function = caller_frame.f_code.co_name

    args, _, _, values = inspect.getargvalues(caller_frame)
    args_info = ", ".join(f"{arg}={values[arg]!r}" for arg in args)
        
    print(Fore.WHITE + "====================================================================================================== FAILURES ======================================================================================================")
    print(Style.BRIGHT + Fore.RED + f"___________________________________________________________________________________________ {current_function} ___________________________________________________________________________________________")
    print(Fore.BLUE + Fore.GREEN + f"   {current_function}" + Fore.YELLOW + f"({args_info})")
    print(Fore.RED + f"        assert (span_element.text == expected_value)")
    print(Fore.RED + f"E       AssertionError: assert '{value}' == '{expected_value}'")
    print(Fore.RED + f"E         ")
    print(Fore.RED + f"        - {value}")
    print(Fore.RED + f"        + {expected_value}")
    print(Fore.RED + "\n" + f"{script_name}" + Fore.WHITE +f"::{line_number}: AssertionError")  # Replace with actual script name and line number

###Get###
def get_method(path,expected_value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    span_element = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    try:
        assert (span_element.text == expected_value)
        global nb_passed
        nb_passed += 1
        
        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(span_element.text, expected_value)
        global nb_failed
        nb_failed += 1
        
        list_of_functions.append((get_function_name(),-1))
    return 

###Get Names###
def get_names_method(path,expected_value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    edit_button = tr_element.find_element(By.XPATH, '//button[@title="Edit parameter value" ]')
    if (edit_button):
        access = "writable"
    else:
        access = "not-writable"

    try:
        assert (expected_value == access)
        global nb_passed
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(expected_value, access)
        global nb_failed
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return 

###Set###
def set_method_bool(path,value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    tr_element.find_element(By.XPATH, '//button[@title="Edit parameter value" ]').click()
    time.sleep(1)
    xpath =  "//select/option[text()='{}']".format(value)
    driver.find_element(By.XPATH, xpath).click()
    time.sleep(1)
    driver.find_element(By.XPATH, '//button[@title="Queue task" and @class="primary"]').click()
    time.sleep(1)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    span_element = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    try:
        assert (span_element.text == value)
        global nb_passed
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(span_element.text, value)
        global nb_failed
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return 

###Set###
def set_method_text(path,value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    tr_element.find_element(By.XPATH, '//button[@title="Edit parameter value" ]').click()
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//div[@class="drawer"]//div[@class="staging"]//input[@type="text"]').send_keys(value)
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Queue task" and @class="primary"]').click()
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(1.5)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    span_element = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    try:
        assert (span_element.text == value)
        global nb_passed 
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(span_element.text, value)
        global nb_failed 
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return 

#find number
def find_number(number_path):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(number_path)
    time.sleep(2)    
    xpath = '//tr[td[@class="left"]/span[@title="{}" and @class="long-text"] and td[@class="right"]/button[@title="Refresh tree"]]'.format(number_path)
    tr_element = driver.find_element(By.XPATH, xpath)
    tr_element.find_element(By.XPATH, './/button[@title="Refresh tree"]').click()
    time.sleep(1)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(2)
    nubmer = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    return nubmer.text


###Add###
def add_method(path,number_path):

    nb_before = find_number(number_path)
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    xpath = '//tr[td[@class="left"]/span[@title="{}" and @class="long-text"] and td[@class="right"]/button[@title="Refresh tree"]]'.format(path)
    tr_element = driver.find_element(By.XPATH, xpath)   
    tr_element.find_element(By.XPATH, './/button[@title="Create a new instance"]').click()
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(2)
    nb_after = find_number(number_path)
    try:
        assert (int(nb_after) == int(nb_before) + 1)
        global nb_passed
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(int(nb_after) , int(nb_before))
        global nb_failed
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return
   

###Delete###
def del_method(path,number_path):
    nb_before = find_number(number_path)
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)    
    xpath = '//tr[td[@class="left"]/span[@title="{}" and @class="long-text"] and td[@class="right"]/button[@title="Refresh tree"]]'.format(path)
    tr_element = driver.find_element(By.XPATH, xpath) 
    tr_element.find_element(By.XPATH, './/button[@title="Delete this instance"]').click()
    time.sleep(2)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(2)
    nb_after = find_number(number_path)
    try:
        assert (int(nb_after) == int(nb_before) - 1)
        global nb_passed
        nb_passed += 1

        list_of_functions.append((get_function_name(),1))
    except:
        expect_return(int(nb_after) , int(nb_before))
        global nb_failed
        nb_failed += 1

        list_of_functions.append((get_function_name(),-1))
    return

def short_test_summary():
    print(Style.BRIGHT + Fore.BLUE + '\n' + "============================================================================================== short test summary info ===============================================================================================")
    for i in list_of_functions:
        if(i[1] == 1):
            print(Fore.GREEN + '\n' +"Passed :" + Fore.WHITE + f"   {i[0]}")
        else:
            print(Fore.RED + '\n' + "Failed :" + Fore.WHITE + f"   {i[0]}")
    print(Style.BRIGHT + Fore.RED + '\n' + f"=============================================================================================== {nb_failed} failed, " + Fore.GREEN + f" {nb_passed} passed " + Fore.RED + " ===============================================================================================")

login_and_select()

summon()
refresh_parameters()

reboot_rpc()
pushfile_rpc("conf_file")
upgrade_firmware("openwrt-ipq40xx-generic-wallys_dr40x9-squashfs-sysupgrade.bin")
get_method("Device.Ethernet.Interface.1.Name","wan")
get_method("Device.WiFi.Radio.1.Enable","false")
set_method_bool("Device.WiFi.Radio.1.Enable","true")
set_method_text("Device.WiFi.Radio.1.OperatingChannelBandwidth","40MHz")
get_names_method("Device.WiFi.Radio.2.Enable", "writable")
add_method("Device.Ethernet.Link","Device.Ethernet.LinkNumberOfEntries")
del_method("Device.Ethernet.Link.7","Device.Ethernet.LinkNumberOfEntries")

get_method("Device.IP.Interface.1.LowerLayers","Device.Ethernet.Link.1")
get_method("Device.Ethernet.Link.1.Name","br-lan")
get_method("Device.IP.Interface.1.IPv4Address.1.IPAddress","192.168.1.177")


get_method("Device.Cellular.InterfaceNumberOfEntries","1")
get_method("Device.Cellular.Interface.1.Name","cellular_0")
get_method("Device.Cellular.Interface.1.Status","Down")
get_method("Device.Cellular.AccessPointNumberOfEntries","0")
add_method("Device.Cellular.AccessPoint","Device.Cellular.AccessPointNumberOfEntries")
del_method("Device.Ethernet.AccessPoint.1","Device.Cellular.AccessPointNumberOfEntries")

reset_rpc()

short_test_summary()

time.sleep(1)
driver.quit()