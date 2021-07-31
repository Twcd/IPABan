# IPABan
IPABan prevent brute force via RDP protocol and all application using the windows Active Directory

IPABan detect Active Directory logon attempt via the windows event log and block IP after 5 failed attempt with the Windows firewall.
The program work as a windows service and he is very light (less  than 1MB for the moment)


## Features
* Detecting attempt and ban IP for 2 hours
* Automaticly banning IP who reported as "hacker" using Abuse IPDB database at the first connection.
* Banning permantly IP after multiple ban.
* Report when an ip got ban to Abuse IPDB database

## Configuration
This is the default configuration file. This file will be created when you start the soft for the first time. You can edit it and restart the program to load the new configuration.
```json
{
  "banDuration": 3600,
  "IPDBapiKey": "",
  "attemptPermaBan": 3,
  "attempBeforeBan": 5,
  "debugLevel": 0,
   "filterIp": [
    "10.0.0.*",
    "127.0.0.1"
  ]
}
```

## Installation
To use IPABan compile it or download from release page, open powershell and execute this command to install the service.

```powershell
New-Service -Name "IPABan" -BinaryPathName <Path to IPABan>.exe
```
Now you can go to your task manager -> Services -> IPABan right click and press start

## If you want to support me
You can donate Ethereum to this address : 0xacbb51c9d3e9c1e1881f4bfac302d0009ccd07af </br>
Or donate Bitcoin to this address : 1NW9sWeyo38ck2p6G9gB9xT1Kp1LQYiVpT

OR you can contribute to the project.
