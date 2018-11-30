#!/usr/bin/python


import requests
import getpass
import logging
import xml.etree.ElementTree as et
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)



logger = logging.getLogger("c_fetch")
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler("cert_fetch_log")
formatter = logging.Formatter('%(asctime)s %(name)s\t%(levelname)s:\t\t%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def getKey():
    """Fetches the API for the supplied credentials"""
    pano_ip = raw_input("Enter the IP address of your Panorama: ")
    user = raw_input("Enter the username of the account that will be used to"
                     "fetch the LS certificates: ")
    passwd = getpass.getpass("\nEnter the password for the API user: ")
    key_params = {'type' : 'keygen',
                  'user' : user,
                  'password' : passwd}
    key_req = requests.get('https://{}/api/?'.format(pano_ip), params=key_params, verify=False)
    key_xml = et.fromstring(key_req.content)
    if key_req.status_code != 200:
        err = key_xml.find('./result/msg').text
        print "Error retrieving API key:\n\n{}".format(err)
    key = key_xml.find('./result/key').text
    info_dict = {}
    info_dict['pano_ip'] = pano_ip
    info_dict['api_key'] = key
    return info_dict


def getDevices(pano_ip, key):
    """Returns a list of connected firewalls"""
    cmd = "<show><devices><connected></connected></devices></show>"
    dev_params = {'type' : 'op',
                  'cmd' : cmd,
                  'key' : key}
    dev_req = requests.get('https://{}/api/?'.format(pano_ip), params=dev_params, verify=False)
    dev_xml = et.fromstring(dev_req.content)
    devices = dev_xml.findall('./result/devices/*')
    fw_list = []
    for device in devices:
        fw_list.append(device.find('serial').text)
    return fw_list


def delCert(pano_ip, key, dev_list):
    """Deletes existing LS certificate from all firewalls in the supplied list"""
    cmd = "<request><logging-service-forwarding><certificate><delete></delete>" \
          "</certificate></logging-service-forwarding></request>"
    err = 0
    for device in dev_list:
        del_params = {'type' : 'op',
                      'cmd' : cmd,
                      'key' : key,
                      'target' : device}
        del_req = requests.get('https://{}/api/?'.format(pano_ip), params=del_params, verify=False)
        del_xml = et.fromstring(del_req.content)
        #TODO: Error checking & whatnot. Need a system to see what the response looks like.
    if err != 0:
        return err
    return 0


def fetchCert(pano_ip, key, dev_list):
    """Fetches LS certificate for all firewalls in the supplied list"""
    cmd = "<request><logging-service-forwarding><certificate><fetch></fetch>" \
          "</certificate></logging-service-forwarding></request>"
    err = 0
    for device in dev_list:
        fetch_params = {'type' : 'op',
                        'cmd' : cmd,
                        'key' : key,
                        'target' : device}
        fetch_req = requests.get('https://{}/api/?'.format(pano_ip), params=fetch_params, verify=False)
        fetch_xml = et.fromstring(fetch_req.content)
        #TODO: Error checking & whatnot. Need a system to see what the response looks like
    if err != 0:
        return err
    return 0


def fetchInfo(pano_ip, key, dev_list):
    """Fetches LS certificate info for all firewalls in the supplied list"""
    cmd = "<request><logging-service-forwarding><certificate><info></info>" \
          "</certificate></logging-service-forwarding></request>"
    outfile = open('cert_info.log')
    err = 0
    for device in dev_list:
        info_params = {'type' : 'op',
                       'cmd' : cmd,
                       'key' : key,
                       'target' : device}
        info_req = requests.get('https://{}/api/?'.format(pano_ip), params=info_params, verify=False)
        info_xml = et.fromstring(info_req.content)
        cert = info_xml.find('./result').text
        outfile.write('====================BEGIN {}====================\n'.format(device))
        outfile.write(cert)
        outfile.write('====================END {}====================\n'.format(device))
    outfile.close()
    return






def main ():
    i_dict = getKey()
    pano_ip = i_dict['pano_ip']
    api_key = i_dict['api_key']
    device_list = getDevices(pano_ip, api_key)
    delCert(pano_ip, api_key, device_list)
    fetchCert(pano_ip, api_key, device_list)
    fetchInfo(pano_ip, api_key, device_list)




if __name__ == "__main__":
    main()






