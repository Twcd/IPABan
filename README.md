# IPABan
IPABan prevent brute force via RDP protocol


IPABan detect RDP connection attempt via the windows event log and block IP after 5 failed attempt with the Windows firewall.
The program work as a windows service and he is very light (less  than 1MB for the moment)


## Features
* Detecting attempt and ban IP for 2 hours

## Information
Actually we cannot configure the app without coding (ex. Change how many attemp before ban ...)

## Coming soon
* Banning permantly IP after multiple ban.
* Automaticly banning IP who reported as "hacker" using Abuse IPDB database.
* Report when an ip got ban to Abuse IPDB database

## Installation
To use IPABan compile it, open powershell and execute this command to install the service.

```powershell
New-Service -Name "IPABan" -BinaryPathName <Path to IPABan>.exe
```
Now you can go to your task manager -> Service -> IPABan right click and press start

## If you want to support me
You can donate Ethereum to this address : 0xacbb51c9d3e9c1e1881f4bfac302d0009ccd07af </br>
Or donate Bitcoin to this address : 1NW9sWeyo38ck2p6G9gB9xT1Kp1LQYiVpT
