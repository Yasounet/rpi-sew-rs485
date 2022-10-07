import serial

port='/dev/ttyUSB0'
baudrate=9600
parity=serial.PARITY_EVEN
stopbits=serial.STOPBITS_ONE
timeout=0.1
write_timeout=0.1
exclusive=True
loop_time = 0.25