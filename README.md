# NetGUARD
Network Guardian <br/>

Defend host, give voice warnings to sysadmin and generate log files.<br />

## Dependencies

 - libasound-dev libjack-jackd2-dev portaudio19-dev python-pyaudio build-essential python-dev libespeak1 libffi-dev

## Installation

 - git clone https://github.com/m4n3dw0lf/NetGUARD
 - cd NetGUARD && pip install -r requirements.txt
 - ./netguard.py

## Current Features

  - Set static ARP with your gateway.               (Guardian)
  - Report if someone is ARP spoofing the gateway.  (Monitor)
  - Report if you are ARP spoofing the gateway.     (Monitor)

## Coming soon

  - SSH, FTP and Scanners warnings.
  - Multiple access attempts block.
