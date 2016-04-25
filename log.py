import logging
import time
import os
import string

import config 
from utilities import *


def log_init():
	if not os.path.isdir(config.LOG_PATH):
		os.makedirs(config.LOG_PATH)
	t =  time.strftime("%y%m%d_%H%M%S", time.localtime(time.time()))
	#logging.basicConfig(format='[%(asctime)s] %(levelname)-8s %(name)s %(message)s', level=logging.DEBUG, filename="re.log")
	logging.basicConfig(format='[%(asctime)s] %(levelname)-8s %(message)s', level=logging.DEBUG, filename=config.LOG_PATH+"%s.log" % t , filemode="w")
	console_log = logging.StreamHandler()
	console_log.setFormatter(logging.Formatter('[%(asctime)s] %(message)s', "%H:%M:%S"))
	logging.getLogger("").addHandler(console_log) # Add console logger

def _pre_process(msg, dbg= None):
	# Cut string and make it printable.	
	msg = convert_to_printable(cut(msg))
	if dbg is not None:
		msg = "<%5d:%5d> "%(dbg.pid,dbg.tid) + msg
	return msg

def i(msg, dbg= None):
	msg = _pre_process(msg,dbg)
	logging.getLogger("").info(msg)

def w(msg, dbg= None):
	msg = _pre_process(msg,dbg)
	logging.getLogger("").warn(msg)

def d(msg, dbg= None):
	msg = _pre_process(msg,dbg)
	logging.getLogger("").debug(msg)

def e(msg, dbg= None):
	msg = _pre_process(msg,dbg)
	logging.getLogger("").error(msg)

