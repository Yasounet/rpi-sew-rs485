import utils


class MoviMotVFD:

    user_data_types = {
        "3_Cyclical": 0x5,
        "3_Acyclical": 0x85,
    }

    _SD1 = 0x02  # Busmaster start delimiter

    _SPEED_MULTIPLIER = 0.0061
    _SPEED_MAX_DEC = 16384
    _SPEED_MIN_DEC = -_SPEED_MAX_DEC
    _RAMP_MULTIPLIER = 1000
    _RAMP_MAX_DEC = 10000
    _RAMP_MIN_DEC = 100

    def __init__(self, config):
        # print(f"creating vfd with config: {config}")
        self._config = config

        self.name = config["Name"]
        self.address = int(config["Address"])
        self.cw_addr = int(config["CW_START_ADDR"])
        self.sw_addr = int(config["SW_START_ADDR"])

        self._udt = self.user_data_types.get(
            config["UserDataType"], self.user_data_types['3_Cyclical'])
        self._control_word = utils.ControlCommands.NONE.value
        self._speed = int(config["DefaultVelocity"])
        self._ramp = float(config["Ramp"])

    def create_packet(self):

        # beginning of the packet, always the same based on config
        packet = bytearray([self._SD1, self.address, self._udt])

        #  append control word
        packet += self._control_word.to_bytes(2, "big", signed=True)

        # append vfd setpoint speed
        packet += self._speed_to_coded(self._speed)

        # if we are using three word control, append ramp
        packet += self._ramp_to_coded(self._ramp)

        # calculate and append crc
        packet += utils.calculate_bcc(packet)

        return packet

    def update_params(self, controlword, speed, ramp):

        self._control_word = controlword
        self._speed = speed
        self._ramp = ramp

        return True

    def _ramp_to_coded(self, ramp=None):

        if ramp is None:
            raise Exception("Ramp value is empty")

        temp_ramp = int(ramp * self._RAMP_MULTIPLIER)
        temp_ramp = utils.py_clip(
            temp_ramp, self._RAMP_MIN_DEC, self._RAMP_MAX_DEC)
        coded_ramp = temp_ramp.to_bytes(2, "big", signed=True)

        return coded_ramp

    def _speed_to_coded(self, speed=None):

        if speed is None:
            raise Exception("Speed value is empty")

        speed_temp = round(speed / self._SPEED_MULTIPLIER)
        speed_temp = utils.py_clip(
            speed_temp, self._SPEED_MIN_DEC, self._SPEED_MAX_DEC)
        coded_speed = speed_temp.to_bytes(2, "big", signed=True)

        return coded_speed
