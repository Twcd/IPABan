# IPABan
IPABan prevent brute force via RDP protocol


IPABan detect RDP connection attempt via the windows event log and block IP after 5 failed attempt with the Windows firewall.
The program work as a windows service and he is very light (less  than 1MB for the moment)


## Features
* Detecting attempt and ban IP for 2 hours

## Coming soon
* Banning permantly IP after multiple ban.
* Automaticly banning IP who reported as "hacker" using Abuse IPDB database.
* Report when an ip got ban to Abuse IPDB database

