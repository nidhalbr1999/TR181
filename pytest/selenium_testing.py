from selenium import webdriver  
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time  
import re  
from colorama import Fore, Style, init
import inspect
import paramiko
import pytest

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
    time.sleep(50)
    return reboot

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
    return reset

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
    return res

###Upgrade###
def upgrade_firmware(filename):
    pushfile_rpc(filename)
    time.sleep(60)
    driver.find_element(By.XPATH, '//button[@title="Initiate session and refresh basic parameters"]').click()
    if (WebDriverWait(driver, 20).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: No contact from CPE'))):
        reboot = True
    else:
        reboot = False

    time.sleep(60)
    return reboot



###Refresh###
def refresh_parameters():
    m_element = driver.find_element(By.XPATH, '//m')
    numbers = re.findall(r'\d+', m_element.text)
    if (numbers[0] == numbers[1]):
        tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@title="Device" and @class="long-text"] and td[@class="right"]/button[@title="Refresh tree"]]')
        tr_element.find_element(By.XPATH, './/button[@title="Refresh tree"]').click()
        driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
        time.sleep(180)


###Get###
def get_method(path,expected_value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    span_element = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    res = dict()
    res['value'] = span_element.text
    res['expected_value'] = expected_value
    return res

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
    res = dict()
    res['value'] = access
    res['expected_value'] = expected_value
    return res

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
    res = dict()
    res['value'] = span_element.text
    res['expected_value'] = value
    return res

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
    res = dict()
    res['value'] = span_element.text
    res['expected_value'] = value
    return res

###Set2###
def set_method_text_number(path,value):
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').clear()
    driver.find_element(By.XPATH, '//input[@placeholder="Search parameters"]').send_keys(path)
    time.sleep(2)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    tr_element.find_element(By.XPATH, '//button[@title="Edit parameter value" ]').click()
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//div[@class="drawer"]//div[@class="staging"]//input[@type="number"]').send_keys(value)
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Queue task" and @class="primary"]').click()
    time.sleep(1.5)
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(1.5)
    tr_element = driver.find_element(By.XPATH, '//tr[td[@class="left"]/span[@class="long-text"] and td[@class="right"]/span[@class="parameter-value"]]')
    span_element = tr_element.find_element(By.XPATH, './/span[@class="parameter-value"]')
    res = dict()
    res['value'] = span_element.text
    res['expected_value'] = value
    return res
    

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
    time.sleep(1)
    WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    time.sleep(3)
    tr_element.find_element(By.XPATH, './/button[@title="Refresh tree"]').click()
    driver.find_element(By.XPATH, '//button[@title="Commit queued tasks" and @class="primary"]').click()
    time.sleep(30)
    #WebDriverWait(driver, 200).until(EC.text_to_be_present_in_element((By.XPATH, '//div'), 'ABCDEF-Luceor-ABCDEF123456: Task(s) committed'))
    nb_after = find_number(number_path)
    time.sleep(4)

    res = dict()
    res['nb_after'] = int(nb_after)
    res['nb_before'] = int(nb_before)
    return res
    
   

###Delete###
def del_method(path,number_path):

    nb_before = find_number(number_path)
    if not (path.split('.')[-1].isdigit()):
        path = path + ".{}".format(nb_before)
    
    
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
    res = dict()
    res['nb_after'] = int(nb_after)
    res['nb_before'] = int(nb_before)
    return res
    