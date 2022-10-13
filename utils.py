from enum import Enum, IntFlag
from struct import unpack

class CPUStatus(Enum):
    UNKNOWN = 'S7CpuStatusUnknown'
    STOP = 'S7CpuStatusStop'
    RUN = 'S7CpuStatusRun'

class ControlCommands(Enum):
    NONE = 0
    ENABLE = 0b00000110
    STOP = 1 << 1
    BRAKE_WHEN_STOP = 1 << 9
    RESET = 1 << 6
    RELEASE_BREAK = 1 << 8
    QUICK_STOP = BRAKE_WHEN_STOP + STOP


class StatusWordB0(IntFlag):
    OUTPUT_STAGE_ENABLED = 1
    INVERTER_READY = 2
    PO_DATA_ENABLED = 4
    ERROR = 32


class StatusWordB1(IntFlag):
    VDC_OPERATION = 0
    NO_ENABLE = 2
    ENABLE = 4
    MANUAL_Operation = 18


def py_clip(x, l, u): return l if x < l else u if x > u else x


def calculate_bcc(packet):
    checksum = 0
    for el in packet:
        checksum ^= el

    return bytes([checksum])


def packet_as_printable_hex(packet):

    return ('-'.join(hex(x) for x in packet))


def parse_control_packet(packet):

    command = unpack(">BBBHhHB", packet)
    (sd1, adr, typ, cw, speed, ramp, bcc) = command

    ramp = float(ramp/1000)

    speed = round(speed * 0.0061)

    check_bcc = calculate_bcc(packet[:-1])

    parsed_cw = cw_to_enum(cw)

    return f'src: {"plc" if sd1 == 0x02 else "invalid"}, addr: {adr}, comm: {typ}, cw: {parsed_cw}, speed: {speed}, ramp: {ramp}, bcc: {"valid" if bytes([bcc])==check_bcc else "invalid"}'


def cw_to_enum(cw):
    try:
        parsed_cw = ControlCommands(cw)
    except ValueError:
        parsed_cw = f'unknown command: {cw}'
    return parsed_cw


def parse_status_packet(packet):

    resp = unpack(">BBBHHHB", packet)
    (sd2, adr, typ, sw1, current, sw2, bcc) = resp
    check_bcc = calculate_bcc(packet[:-1])

    return (f'src: {"vfd" if sd2 == 0x1D else "invalid"}, addr: {adr}, comm: {typ}, sw1: {sw1}, curr: {current}, sw2: {sw2}, bcc: {"valid" if bytes([bcc])==check_bcc else "invalid"}')
