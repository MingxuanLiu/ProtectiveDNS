# -*- coding:utf-8 -*-
import logging
import coloredlogs


# 日志初始化
def init_log(filename):
    """
    :param filename --> log save file
    :return logger
    """
    formattler = '[%(levelname)-7s] [%(process)d] [%(asctime)s] [%(filename)-8s:%(lineno)-3d] %(message)s'
    fmt = logging.Formatter(formattler) 
    logger = logging.getLogger()
    coloredlogs.install(level=logging.INFO, fmt=formattler)
    file_handler = logging.FileHandler(filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)
    try:
        logging.getLogger("scapy").setLevel(logging.WARNING)
        logging.getLogger("matplotlib").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("asyncpool").setLevel(logging.WARNING)
        logging.getLogger("boto3").setLevel(logging.WARNING)
        logging.getLogger("botocore").setLevel(logging.WARNING)
        logging.getLogger("WorkerPool").setLevel(logging.WARNING)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        logging.getLogger("geoip2").setLevel(logging.WARNING)
        logging.getLogger("pymongo").setLevel(logging.WARNING)
    except Exception as e:
        pass
    return logger
