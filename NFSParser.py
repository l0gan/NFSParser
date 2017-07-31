#! /bin/python
import random
import subprocess
import socket, struct, fcntl
import string
import os
import sys
import time
from time import strftime, gmtime
from argparse import ArgumentParser
import re
from netaddr import IPNetwork

ver = "0.2017.7.31"

print("""
     __  ___  __    ___
  /\ \ \/ __\/ _\  / _ \__ _ _ __ ___  ___ _ __
 /  \/ / _\  \ \  / /_)/ _` | '__/ __|/ _ \ '__|
/ /\  / /    _\ \/ ___/ (_| | |  \__ \  __/ |
\_\ \/\/     \__/\/    \__,_|_|  |___/\___|_|


                                Version: """ + ver + """
    """)
parser = ArgumentParser(description='Search a network for NFS shares and parse shares for sensitive data.')
parser.add_argument('--ip', '-i', help='IP or subnet (192.168.1.55 or 192.168.1.0/24)')
parser.add_argument('--IP', '-I', help='File with list of IP addresses. (One per line)')

args = parser.parse_args()
if not len(sys.argv) > 1:
        parser.print_help()
        exit()


def hostConnect(ip, port):
    host = ip
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sd.settimeout(2)
    sd.connect((host, port))
    nfsmount(host)
    sd.close()

def portScan(port, ipsubnet):
    IP = []
    print('[+] Scanning ' + ipsubnet + ' for port ' + str(port))
    if "/" in ipsubnet:
        for ip in IPNetwork(ipsubnet):
            try:
                hostConnect(str(ip), port)
            except socket.error:
                pass
    else:
        host = ipsubnet
        try:
            hostConnect(host, port)
        except socket.error:
            pass

def nfsmount(ip):
    root = 'mnt'
    if not os.path.exists(root):
        os.makedirs(root)
    results=subprocess.check_output('showmount -e ' + ip, shell=True)
    results=results.split('\n')
    anonNFS=results[1]
    if '*' in anonNFS or 'anonymous' in anonNFS:
        print('[!] Anonymous NFS share found:  ' + ip)
        results=anonNFS.split(' ')[0]
        results=str(results)
        print('[+] Mounting NFS share: ' + results)
        subprocess.check_output('mount -t nfs '+ ip + ':' + results + ' ' + root, shell=True)
        print('[+] NFS share mounted to ' + root)
        subprocess.check_output('cd ' + root, shell=True)
        fileSearch(root)
        # unmount share
        print('[+] Unmounting mount: ' + results)
        subprocess.check_output('umount ' + root, shell=True)
    else:
        print('[-] No Anonymous NFS shares found')

def fileSearch(root):
    print('[+] Searching for files in: ' + root)
    for path, subdirs, files in os.walk(root):
        for name in files:
            ssnSearch(path, name)
            CCSearch(path, name)
            #self.passSearch(files, path)
        for subdir in subdirs:
            fileSearch(subdir)

def passSearch(files, path):
    print('[+] Looking for password files')
    for file in files:
        if 'password' in file.lower():
            print('[!] Potential Password File: ' + path + file)

def CCSearch(path, name):
    print('[+] Looking for Credit Card Numbers in: ' + path + '/' + name)
    with open(path + '/' + name, 'r') as f:
        for line, number in enumerate(f, 1):
            prog = re.compile('(\D|^)\%?[Bb]\d{13,19}\^[\-\/\.\w\s]{2,26}\^[0-9][0-9][01][0-9][0-9]{3}|(\D|^)\;\d{13,19}\=(\d{3}|)(\d{4}|\=)|[1-9][0-9]{2}\-[0-9]{2}\-[0-9]{4}\^\d|(\D|^)5[1-5][0-9]{2}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)|(\D|^)4[0-9]{3}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)|(\D|^)(34|37)[0-9]{2}(\ |\-|)[0-9]{6}(\ |\-|)[0-9]{5}(\D|$)|(\D|^)30[0-5][0-9](\ |\-|)[0-9]{6}(\ |\-|)[0-9]{4}(\D|$)|(\D|^)(36|38)[0-9]{2}(\ |\-|)[0-9]{6}(\ |\-|)[0-9]{4}(\D|$)|(\D|^)6011(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)')
            result = prog.search(number)
            if result:
                print('[!] MATCH: Credit Card Data found in line number: ' + str(line))
        f.close()

def ssnSearch(path, name):
    print('[+] Looking for SSNs in: ' + path + '/' + name)
    with open(path + '/' + name, 'r') as f:
        for line, number in enumerate(f, 1):
            # Look for SSNs with - and with spaces
            prog = re.compile('(\D|^)[0-9]{3}\-[0-9]{2}\-[0-9]{4}(\D|$)|(\D|^)[0-9]{3}\ [0-9]{2}\ [0-9]{4}(\D|$)')
            result = prog.search(number)
            if result:
                print('[!] MATCH: SSN Data found in line number: ' + str(line))
        f.close()

def main():
    IPAdd = args.ip
    IPTextFile = args.IP
    port = 2049
    if IPAdd:
        portScan(port, IPAdd)
    elif IPTextFile:
        with open(IPTextFile, "r") as f:
            for IPAdd in f:
                IPAdd = IPAdd.rstrip()
                portScan(port, IPAdd)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

