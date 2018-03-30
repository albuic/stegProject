import logging


def setup_custom_logger(name):
    formatter = logging.Formatter(fmt='%(asctime)s - %(levelname)s - %(module)s - %(message)s')

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)

    logging.addLevelName(5, 'TRACE')
    logging.addLevelName(25, 'NORMAL')

    logger = logging.getLogger(name)
    logger.setLevel(25)
    logger.addHandler(handler)
    return logger
