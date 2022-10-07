import struct
import snap7
import time


client = snap7.client.Client()


client.connect('192.168.0.125', 0, 0)

data = client.db_read(500, 0, 10)

print(len(data))

addr, cw, speed, ramp = struct.unpack('>BxHbxf', data)

print(f'Addr: {addr}, cw: {cw}, speed: {speed}, ramp: {ramp}')

addr = 5
cw = 11
speed = 100
ramp = 0.5

new_data = struct.pack('>BxHBxf', addr, cw, speed, ramp)

client.db_write(500, 10, new_data)

time.sleep(1)
