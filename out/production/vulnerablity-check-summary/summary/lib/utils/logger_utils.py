import logging
import sys
from pathlib import Path


class CustomFormatter(logging.Formatter):

    green = "\x1b[92;21m"
    cyan = "\x1b[96;21m"
    yellow = "\x1b[93;21m"
    red = "\x1b[91;21m"
    reset = "\x1b[0m"
    tag = "[%(levelname)s]"
    message = " %(message)s"
    file = " - (%(filename)s:%(lineno)d)"

    FORMATS = {
        logging.DEBUG: cyan + tag + reset + message + file,
        logging.INFO: green + tag + reset + message + file,
        logging.WARNING: yellow + tag + reset + message + file,
        logging.ERROR: red + tag + reset + message + file,
        logging.FATAL: red + tag + reset + message + file
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


def get_logger(script_name: str, debug: bool = False, logfile: str = None):
    logger = logging.getLogger(script_name)

    # verbosity
    level = logging.DEBUG if debug else logging.INFO
    logger.setLevel(level)

    # console output
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(CustomFormatter())
    logger.addHandler(stdout_handler)

    # logfile output
    if logfile is not None:
        logfile_path = Path(logfile)
        logfile_path.parent.mkdir(parents=True, exist_ok=True)
        output_file_handler = logging.FileHandler(logfile)
        output_file_handler.setFormatter(CustomFormatter())
        logger.addHandler(output_file_handler)

    return logger
