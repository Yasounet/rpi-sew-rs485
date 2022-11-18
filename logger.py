import logging
import logging.handlers as handlers
from pathlib import Path

CURRENT_PATH = Path(__file__).parent
LOG_DIR = 'logs/'
LOG_PATH = CURRENT_PATH.joinpath(LOG_DIR)

RS_LOG_PATH = LOG_PATH.joinpath('rs485.log')
S7_LOG_PATH = LOG_PATH.joinpath('s7.log')
C_LOG_PATH = LOG_PATH.joinpath('console.log')

FORMAT = logging.Formatter('[%(levelname)s] - %(message)s')
LOG_LEVEL = logging.CRITICAL


def setup_console_logger(name, log_file, level=logging.INFO, log2file=False):

    handler = logging.StreamHandler()
    handler.setFormatter(FORMAT)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    if log2file:
        handler = handlers.TimedRotatingFileHandler(filename=log_file, when='midnight', interval=1)
        handler.setFormatter(FORMAT)
        logger.addHandler(handler)

    return logger


def setup_thread_logger(name, log_file, level=logging.INFO):

    handler = handlers.TimedRotatingFileHandler(
        filename=log_file, when='midnight', interval=1)
    handler.setFormatter(FORMAT)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


rs485_logger = setup_thread_logger('rs485_logger', RS_LOG_PATH, level=LOG_LEVEL)
s7_logger = setup_thread_logger('udp_logger', S7_LOG_PATH, level=LOG_LEVEL)
c_logger = setup_console_logger('console_logger', C_LOG_PATH, level=LOG_LEVEL)
