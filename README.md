IEC-104 rogue command injector.
PROOF-OF-CONCEPT CODE
UNSANCTIONED USE FORBIDDEN! 
2018. Author: Lockout
Version: 0.3.5

usage: iec104inj.py [-h] -t TARGET -i IOA -s STATE -e ETH [-T TX] [-R RX]
                    [--port PORT] [--timeout TIMEOUT]
                    [--payloadsize PAYLOADSIZE] [--nocolor] [--startdtonly]
                    [--sleep SLEEP]

Required arguments:
  -t TARGET, --target TARGET
                        Target RTU IPv4 address
  -i IOA, --ioa IOA     Information Object Address (IOA) number
  -s STATE, --state STATE
                        IOA switch state ON=1/OFF=0
  -e ETH, --eth ETH     Network interface name

Optional arguments:
  -T TX, --tx TX        Transmission identifier. Default = 0
  -R RX, --rx RX        Reception identifier. Default = 0
  --port PORT           Target IEC104 port. Default = 2404
  --timeout TIMEOUT     Connection timeout in seconds. Default = 1
  --payloadsize PAYLOADSIZE
                        Payload size to receive in bytes. Default = 1000
  --nocolor             Disable color print
  --startdtonly         Perform only initial step to verify successful STARTDT
  --sleep SLEEP         Sleep timer in seconds between the packets. Default =
                        0.5
