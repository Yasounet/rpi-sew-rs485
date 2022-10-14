from copy import deepcopy
import time
import serial
import os
import configparser
import utils
import queue
import signal
from logger import c_logger, rs485_logger, s7_logger
import logging
from config import rs485_config, s7_config
import snap7

from timer import RepeatedTimer
from struct import unpack, pack

rs485_queue = queue.Queue()
s7_queue = queue.Queue()


class RPI4_to_SEW:
    def __init__(self, nodename, config_path="/config/config.ini", debug=False):
        self._nodename = nodename
        self._config_path = config_path
        self._inverters = []
        self.config = configparser.ConfigParser()
        self.read_config()
        self.debug = debug
        self.rs485_rt = RepeatedTimer(rs485_config.loop_time, self.rs485_loop)
        self.s7_rt = RepeatedTimer(s7_config.loop_time, self.s7_loop)
        self._terminate = False
        self.serial = None
        self.serial_connected = False
        self.s7_client = None
        self.s7_connected = False
        self.s7_in_run = False
        self._startup = False

        signal.signal(signal.SIGINT, self.catch)

    def startup(self):

        self.populate_vfds()

        if not self.connect_serial():
            c_logger.error("Could not connect to serial")
            return False

        self.connect_s7()

        if not self.start_threads():
            c_logger.error("Could not start comm threads")
            return False

        self._startup = True
        return True

    # ----------------------- SERIAL STUFF -----------------------

    def connect_serial(self, logger=rs485_logger):

        if self.debug:
            c_logger.debug("Connected to fake serial")
            return True

        try:
            if self.serial == None:
                self.serial = serial.Serial(port=rs485_config.port, baudrate=rs485_config.baudrate, parity=rs485_config.parity,
                                            stopbits=rs485_config.stopbits, timeout=rs485_config.timeout, write_timeout=rs485_config.write_timeout,)  # exclusive=True,)
                c_logger.info(
                    f'Sucessfully created and connected serial connection at port: {self.serial.port}')
            else:
                if self.serial.isOpen():
                    self.serial.close()
                    c_logger.debug('Disconnected from serial')
                    return False
                else:
                    self.serial.open()
                    c_logger.debug('Reconnected')

        except serial.SerialException as e:
            logger.debug(e)
            return False

        return True

    def is_serial_connected(self):

        if self.debug:
            return True

        try:
            return self.serial.isOpen()

        except:
            c_logger.debug('Serial not connected')
            return False

    def close_serial(self):
        c_logger.debug('Closing serial')

        if self.serial is not None:
            self.serial.close()

    def rs485_loop(self, logger=rs485_logger):

        logger.info(' --- RS485 LOOP START --- ')
        start = time.perf_counter()
        logger.debug(f'current time = {start}')

        if self._terminate:
            logger.debug('Node terminating, skipping loop')
            return  # return if we are terminating node

        if not self.s7_connected or not self.s7_in_run:

            logger.error(f'No connection to PLC or CPU in stop mode')
            logger.warning(f'Sending empty commands to drives')
            for (vfd_addr, vfd) in self._inverters:
                vfd.update_params(0, 0, 0)

            packets = self.create_packets()
            responses = self.send_packets(packets)

            return

        if not self.is_serial_connected():
            logger.error("RS485 not connected, reconnecting")
            self.connect_serial()
            return

        if not s7_queue.empty():
            logger.debug('s7_queue not empty')

            with s7_queue.mutex:
                try:
                    commands = deepcopy(s7_queue.queue[-1])
                except IndexError:
                    commands = []
                s7_queue.queue.clear()

            for (addr, cw, speed, ramp) in commands:

                vfd = self.get_vfd_by_id(addr)

                if vfd:
                    vfd.update_params(cw, speed, ramp)
                    logger.info(
                        f'Updating VFD: {addr} with cw: {cw}, speed: {speed}, ramp: {ramp}')
                else:
                    logger.error(
                        f'Trying to change params of VFD: {addr} that doesnt exist')

        else:
            logger.debug('no updates for vfd commands')

        packets = self.create_packets()
        logger.info(f'Creating {len(packets)} packets...')

        for packet in packets:
            message = utils.parse_control_packet(packet)
            logger.debug(message)

        logger.info('Sending control packets to VFDs...')
        logger.info('Receiving responses...')
        responses = self.send_packets(packets)
        if responses is None:
            logger.debug("Received no responses")
            return
        logger.debug(
            F'Putting {len(responses)} responses in rs485_queue')
        rs485_queue.put(responses)

        for response in responses:
            logger.debug(utils.parse_status_packet(response))

        end = time.perf_counter()
        logger.info(f"Loop took {end - start} time")
    # ----------------------- SIEMENS S7 -----------------------

    def connect_s7(self, logger=s7_logger):

        self.s7_connected = False  # Is this really necessary?

        if self.debug:
            logger.debug("Connected to fake Siemens PLC")
            self.s7_connected = True
            return True

        try:
            if self.s7_client is None or not self.s7_connected:
                logger.debug("Creating snap7 client")
                # Recreating whole client appears to have more success when reconnecting, any clues why?
                self.s7_client = snap7.client.Client()
                self.s7_client.connect(
                    s7_config.IP_ADDR, s7_config.RACK, s7_config.SLOT)  # Tends to throw a lot of random errors when just trying to reconnect
                logger.info(
                    f"Connected to {s7_config.IP_ADDR} rack {s7_config.RACK} slot {s7_config.SLOT}")
                self.s7_connected = True
            else:
                # This should never really happen
                logger.error("Reconnection while connected")
        except Exception as e:
            logger.error(f'Error while reconnecting: {e}')
            return False

        return True

    def s7_loop(self, logger=s7_logger):

        logger.info(' --- S7 LOOP START --- ')
        start = time.perf_counter()
        logger.debug(f'current time = {start}')

        if self._terminate:
            logger.debug('Node terminating, skipping loop')
            return

        logger.info("Checking CPU Status")

        if not self.s7_check_running():
            if not self.s7_connected:
                logger.warning('We are not connected')
                return self.connect_s7()
            logger.warning('CPU in stop mode')

        logger.info('CPU in RUN Mode')
        logger.info("Reading new data from PLC")

        commands = []

        for (_, vfd) in self._inverters:  # for each inverter

            addr, cw, speed, ramp = self.s7_read_from_PLC(
                start=vfd._cw_addr)  # read control word from PLC

            parsed_cw = utils.cw_to_enum(cw)

            logger.debug(
                f'Addr: {addr}, cw: {parsed_cw}, speed: {speed}, ramp: {ramp}')

            # append command tuple to commands
            commands.append((addr, cw, speed, ramp))

        logger.info("Sending commands to RS485 thread")
        logger.debug(f"Placing {len(commands)} commands in s7_queue")
        s7_queue.put(commands)  # place commands in queue for rs485 thread

        addr = 0

        logger.info("Reading new data from RS485 thread")
        if not rs485_queue.empty():

            # only read most recent status from rs485 queue

            with rs485_queue.mutex:
                row = deepcopy(rs485_queue.queue[-1])
                rs485_queue.queue.clear()  # clear queue

            for response in row:
                logger.debug(utils.parse_status_packet(response))

            for (vfd_addr, vfd) in self._inverters:  # for every inverter in config list
                logger.debug(f"creating status for vfd: {vfd_addr}")
                sent = False

                logger.debug(f"trying to match one of rs485 responses")

                if sent:  # dont update status more than once
                    continue  # continue to next vfd in list

                for id, response in enumerate(row):
                    if response is not None:  # if response existsr
                        if len(response) > 0:  # if response isnt empty
                            addr, sw1, current, sw2 = self.unpack_response(
                                response)  # unpack respose
                        else:
                            logger.debug("Empty response")
                            # row.pop(id)

                    if vfd_addr == addr:  # try to match one of vfds in the config
                        logger.debug(f"response matched, sending data")
                        # write data to plc
                        self.s7_write_to_PLC(vfd_addr, sw1, current, sw2)
                        sent = True
                        # pop response so we dont have to parse it more than once
                        # row.pop(id)
                        break  # break out of response parsing loop, we already found a match

                else:  # if we didnt match any data for vfd in responses
                    logger.warning(
                        f"didnt match any response for vfd: {vfd_addr}, sending empty data")  # warn user
                    # write empty data to plc
                    self.s7_write_to_PLC(vfd_addr, 0, 0, 0)

            logger.info("Sending status data back to PLC")
            end = time.perf_counter()
            logger.info(f"Loop took {end - start} time")

    def s7_write_to_PLC(self, addr, sw1, current, sw2):
        new_data = pack('>BxHHHxx', addr, sw1, current, sw2)

        vfd = self.get_vfd_by_id(addr)

        if not self.s7_client.get_connected():
            return False

        try:
            self.s7_client.db_write(s7_config.DB_NUM, vfd._sw_addr, new_data)
        except Exception as e:
            c_logger.error(
                F'incorrect message while writing to PLC - dbnum: {s7_config.DB_NUM}, sw_address: {vfd._sw_addr}, payload: {new_data} ')
            self.s7_client.disconnect()

    def unpack_response(self, response):
        resp = unpack(">BBBHHHB", response)
        (sd2, addr, typ, sw1, current, sw2, bcc) = resp
        return addr, sw1, current, sw2

    def s7_check_running(self, logger=s7_logger):

        state = None

        try:
            state = self.s7_client.get_cpu_state()
            state = utils.CPUStatus(state)
            logger.debug(state)
        except Exception as e:
            logger.debug(f'Cannot get CPU state: {e}')

        if state is None or state == utils.CPUStatus.UNKNOWN:  # We might be disconnected from PLC?
            self.s7_connected = False  # Force reconnected in s7 loop
            return False

        self.s7_in_run = state == utils.CPUStatus.RUN

        return self.s7_in_run

    def s7_read_from_PLC(self, db_num=s7_config.DB_NUM, start=0, lenght=10):

        if not self.s7_client.get_connected():
            return 0, 0, 0, 0

        try:
            raw_data = self.s7_client.db_read(s7_config.DB_NUM, start, lenght)
            addr, cw, speed, ramp = unpack('>BxHbxf', raw_data)

        except Exception as e:
            self.s7_client.disconnect()
            return 0, 0, 0, 0

        return addr, cw, speed, round(ramp, 2)

    def read_config(self):
        full_path = os.path.realpath(__file__)
        dir_path = os.path.dirname(full_path)
        config_path = dir_path + self._config_path
        c_logger.info(f"Reading config from {config_path}")
        self.config.read(config_path)

    # ----------------------- VFD stuff -----------------------

    def populate_vfds(self):
        c_logger.info("Populating VFDs...")
        for vfd_config in self.config:
            if "VFD" in vfd_config:
                sew_vfd = self.SEW_VFD(self.config[vfd_config])
                addr = sew_vfd.address
                self._inverters.append((addr, sew_vfd))
                c_logger.debug(
                    f"VFD {sew_vfd.name} with address {addr} added")

    def list_vfds(self):
        vfd_list = []
        for (addr, vfd) in self._inverters:
            vfd_list.append((addr, vfd.name))
        return vfd_list

    def get_vfd_by_id(self, addr):

        for (vfd_addr, vfd) in self._inverters:
            if vfd_addr == addr:
                return vfd
        else:
            return None

    def create_packets(self):

        packets = []

        for (_, vfd) in self._inverters:
            packet = vfd.create_packet()
            packets.append(packet)

        return packets

    def send_packets(self, packets):

        if not self.is_serial_connected():
            return []

        if self._terminate:
            return

        responses = []
        raw = None

        for packet in packets:

            try:
                self.serial.write(packet)
                raw = self.serial.read(len(packet))
            except Exception as e:
                self.serial.close()
                c_logger.error(f'read error - {e}')

            responses.append(raw)
        return responses

    def parse_packet(self, packet: bytearray):

        sd2, adr, type, sw1, current, sw2, bcc = unpack(">BBBHHHB", packet)
        c_logger.debug(utils.parse_status_packet(packet))
        resp = [adr, sw1, current]

        return resp

    def start_threads(self):

        # todo implement timeout
        while not (self.rs485_rt.is_running and self.s7_rt.is_running):
            self.rs485_rt.start()
            self.s7_rt.start()

        return True

    def stop_threads(self):

        while self.rs485_rt.is_running:
            self.rs485_rt.stop()
            c_logger.debug('rs485 stopped')

        while self.s7_rt.is_running:
            self.s7_rt.stop()
            c_logger.debug('s7 stopped')

    def loop(self):

        if not self._startup:
            return False

        while not self._terminate:
            time.sleep(2)
            pass

    def terminate(self):
        c_logger.info("Shutting down...")
        self._terminate = True
        try:
            c_logger.info('Stopping threads')
            self.stop_threads()
            c_logger.debug(
                'Threads stopped, sleeping to finish last loop before closing serial')
            time.sleep(1)
        finally:

            c_logger.info('Closing serial connection')
            self.close_serial()

        c_logger.debug('Deleting VFD objects...')
        for (_, vfd) in self._inverters:
            c_logger.debug(f'Deleting {vfd.name}')
            del vfd

    def catch(self, signum, frame):
        self.terminate()

    class SEW_VFD:

        user_data_types = {
            "3_Cyclical": 0x5,
            "3_Acyclical": 0x85,
        }

        SD1 = 0x02  # Busmaster start delimiter

        SPEED_MAX_DEC = 16384
        SPEED_MIN_DEC = -SPEED_MAX_DEC
        RAMP_MAX_DEC = 10000
        RAMP_MIN_DEC = 100

        def __init__(self, config):
            # print(f"creating vfd with config: {config}")
            self.config = config
            self.name = config["Name"]
            self.address = int(config["Address"])
            self.udt = self.user_data_types.get(config["UserDataType"])
            self._control_word = 0
            self._speed = int(config["DefaultVelocity"])
            self._ramp = float(config["Ramp"])
            self._cw_addr = int(config["CW_START_ADDR"])
            self._sw_addr = int(config["SW_START_ADDR"])

        def create_packet(self):

            # beginning of the packet, always the same based on config
            packet = bytearray([self.SD1, self.address, self.udt])

            #  append control word
            packet += self._control_word.to_bytes(2, "big", signed=True)

            # append vfd setpoint speed
            packet += self.speed_to_coded(self._speed)

            # if we are using three word control, append ramp
            packet += self.ramp_to_coded(self._ramp)

            # calculate and append crc
            packet += utils.calculate_bcc(packet)

            return packet

        def ramp_to_coded(self, ramp=None):

            if ramp == None:
                raise Exception("Ramp value is empty")

            temp_ramp = int(ramp * 1000)
            temp_ramp = utils.py_clip(
                temp_ramp, self.RAMP_MIN_DEC, self.RAMP_MAX_DEC)
            coded_ramp = temp_ramp.to_bytes(2, "big", signed=True)

            return coded_ramp

        def speed_to_coded(self, speed=None):

            if speed == None:
                raise Exception("Speed value is empty")

            speed_temp = round(speed / 0.0061)
            speed_temp = utils.py_clip(
                speed_temp, self.SPEED_MIN_DEC, self.SPEED_MAX_DEC)
            coded_speed = speed_temp.to_bytes(2, "big", signed=True)

            return coded_speed

        def update_params(self, controlword, speed, ramp):

            self._control_word = controlword
            self._speed = speed
            self._ramp = ramp

            return True


if __name__ == "__main__":

    rpi = RPI4_to_SEW(
        'RPI_test_node', config_path='/config/config.ini', debug=False)

    rpi.startup()
    rpi.loop()
