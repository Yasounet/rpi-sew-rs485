import logging

LOG_DIR = '/home/ubuntu/workspace/rpi-sew-rs485/logs/'

format = logging.Formatter('[%(levelname)s] - %(message)s')


def setup_console_logger(name=__name__, level=logging.INFO):

    handler = logging.StreamHandler()
    handler.setFormatter(format)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file, mode='w+')
    handler.setFormatter(format)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


rs485_logger = setup_logger(
    'rs485_logger', LOG_DIR + 'rs485.log', level=logging.DEBUG)
s7_logger = setup_logger('udp_logger', LOG_DIR +
                         'udp.log', level=logging.DEBUG)
c_logger = setup_console_logger('console_logger', level=logging.DEBUG)

handler = logging.FileHandler(LOG_DIR + 'console.log', mode='w+')
c_logger.addHandler(handler)
