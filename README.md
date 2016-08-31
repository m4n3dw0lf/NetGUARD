# NetGUARD
Network Guardian v1.0 <br/>

Defend host, give voice warnings to sysadmin and generate log files.<br />

## Dependencies

 - libasound-dev libjack-jackd2-dev portaudio19-dev python-pyaudio build-essential python-dev libespeak1 libffi-dev

## Installation

 - git clone https://github.com/m4n3dw0lf/NetGUARD
 - cd NetGUARD && pip install -r requirements.txt
 - nano config/netguard.cfg (Configure required settings)
 - ./netguard.py -h

## Basics

  > examples:

```
 ./netguard.py --verbose or -v           Start NetGUARD verbosely.
 ./netguard.py --stop or -s              Stop NetGUARD.
 ./netguard.py --help or -h              Print this help message.
```

## Current Features


### Denial Of Service Protection

  - Block connections from host after a TCP/UDP/ICMP flood attack is detected.   (Guardian)
  - Report if someone is performing a TCP/UDP/ICMP flood DoS.	                 (Monitor)

### ARP Protection
  
  - Set static ARP with your gateway.                                       (Guardian)
  - Report if someone is ARP spoofing the gateway.                          (Monitor)
  - Report if you are ARP spoofing the gateway.                             (Monitor)

### SSH Protection

  - Block SSH connections from IP after multiple failed attempts.           (Guardian)
  - Report if someone open a socket with the SSH server.                    (Monitor)

### FTP Protection

  - Block FTP connections from IP after multiple failed attempts.           (Guardian)
  - Report if someone enter a wrong password in the FTP server.             (Monitor)

### SQL Protection

  - Block MySQL connections from IP after multiple failed attempts.         (Guardian)
  - Report if someone enter a wrong password in the MySQL server.           (Monitor)

## Coming soon

  - Scanners warnings and protections.
  - Warnings about host running NetGUARD brute-forcing.
