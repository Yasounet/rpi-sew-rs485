from email import utils
from utils import calculate_bcc, parse_status_packet
import serial
import time

ser = serial.Serial(port='/dev/ttyUSB0', baudrate=9600,
                    parity=serial.PARITY_EVEN,
                    stopbits=serial.STOPBITS_ONE, timeout=5)

stop = bytearray([0x02, 0x01, 0x85, 0x02, 0x00, 0x20, 0x00, 0x0B, 0xB8])

stop += calculate_bcc(stop)

print(len(stop))
print(stop)
while True:
    ser.write(stop)
    resp = ser.read(len(stop))
    print(f'res: {resp}')
    print(parse_status_packet(resp))
    time.sleep(1)
