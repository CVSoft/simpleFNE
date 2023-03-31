# simpleFNE
A simple, barebones FNE for DVMProject's DVMHost, useful as a debugging tool. 

## Requirements
This runs in Python 3.4 or later. It might run in 3.3, but I haven't tested it. It runs using only standard libraries and does not have any dependencies. While only tested on Windows, it should not do anything platform-dependent. 

## Usage
Create a config file, in INI structure, containing your desired options. See the Configuring section for details. 

Then run simpleFNE on the command line with this config file's filename as the only positional argument, e.g. `python simple_fne.py config.ini`. 

Direct your [DVMHost](https://github.com/dvmproject/dvmhost) (or [DVM Packet Inspector](https://github.com/CVSoft/dvm_packet_inspector)) endpoints at this server, and it'll just work. No attempts are made to authenticate DVMHost clients, and any password is accepted (challenge requests are discarded). Since this is intended to be a debugging tool, there is zero security implemented in simpleFNE. 

## Configuring
There are four configurable options in simpleFNE; all of these are in an INI-format file under a section titled FNE. These options are:
* `ip`: the IPv4 address to listen on. 
* `port`: the port number to listen on. 
* `endpoint_timeout`: when an endpoint hasn't produced any traffic after this many seconds (usually due to it disconnecting without informing simpleFNE), it is dropped. 
* `show_pings`: by default, pings are shown in console output; this can cause the console to get cluttered with pings, so setting this option to `false` will prevent pings from being displayed on the console. 

The default configuration is given below:
```
[FNE]
ip: ANY
port: 54000
endpoint_timeout: 120
show_pings: true
```
