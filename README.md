# NFSParser

This is a simple tool to look for open NFS shares. If open NFS shares are found, NFSParser will search for sensitive information. 

So far the information searched for is:

* Files with the name "password" (case insensitive)
* Social Security Numbers
* Credit Card Numbers

Hope to be adding more soon!


# Use:
```
     __  ___  __    ___
  /\ \ \/ __\/ _\  / _ \__ _ _ __ ___  ___ _ __
 /  \/ / _\  \ \  / /_)/ _` | '__/ __|/ _ \ '__|
/ /\  / /    _\ \/ ___/ (_| | |  \__ \  __/ |
\_\ \/\/     \__/\/    \__,_|_|  |___/\___|_|


                                Version: 0.2017.7.30

usage: NFSParser.py [-h] [--ip IP] [--IP IP]

Search a network for NFS shares and parse shares for sensitive data.

optional arguments:
  -h, --help      show this help message and exit
  --ip IP, -i IP  IP or subnet (192.168.1.55 or 192.168.1.0/24)
  --IP IP, -I IP  File with list of IP addresses. (One per line)
```
