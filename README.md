# simpleFNE
A simple, barebones FNE for DVMProject's DVMHost, useful as a debugging tool. 

## Requirements
This runs in Python 3.4 or later. It might run in 3.3, but I haven't tested it. It runs using only standard libraries and does not have any dependencies. While only tested on Windows, it should not do anything platform-dependent. 

## Usage
Create a config file, in INI structure, containing your desired bindhost (`ANY` , port, and expiry timer for dead endpoints. These appear, respectively, in this sample configuration using the default values:  
```
[FNE]
ip: ANY
port: 54000
endpoint_timeout: 120
```

Then run simpleFNE on the command line with this config file's filename as the only positional argument, e.g. `python simple_fne.py config.ini`. 

Direct your [DVMHost](https://github.com/dvmproject/dvmhost) endpoints at this server, and it'll just work. No attempts are made to authenticate DVMHost clients, and any password is accepted (challenge requests are discarded). Since this is intended to be a debugging tool, there is zero security implemented in simpleFNE. 
