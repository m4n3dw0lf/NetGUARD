# NetGUARD
Network Guardian v0.5 <br/>

Defend host, give voice warnings to sysadmin and generate log files.<br />

## Dependencies

 - libasound-dev libjack-jackd2-dev portaudio19-dev python-pyaudio build-essential python-dev libespeak1 libffi-dev

## Installation

 - git clone https://github.com/m4n3dw0lf/NetGUARD
 - cd NetGUARD && pip install -r requirements.txt
 - nano config/netguard.cfg (Configure required settings)
 - ./netguard.py

  > NetGUARD will give voice warnings or you can check log at: log/NetGUARD.log

## Basics

 - Finish NetGUARD with kill -2 to generate a .pcap file with network traffic intercepted by NetGUARD

  > example:

```
# ps -aux | grep NetGUARD
               ...
root      6654 ... python core/NetGUARD.py
               ...

# kill -2 6654
```

## Current Features

  ### ARP Protection
  - Set static ARP with your gateway.                        (Guardian)
  - Report if someone is ARP spoofing the gateway.           (Monitor)
  - Report if you are ARP spoofing the gateway.              (Monitor)

  ### SSH Protection
  - Block SSH packets from IP after multiple failed attempts.(Guardian)
  - Report if someone open a socket with the SSH server.     (Monitor)


## Coming soon

  - FTP,SQL and Scanners warnings.
  - Multiple FTP,SQL access attempts block.
