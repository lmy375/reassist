import string, struct, traceback

from pydbg.defines import *

import log
from info import *
from report import *
import config

def global_entry_hook(hc, dbg):	
	#log.i( "[%s() entering]: Thread-%d at %#x" % (hc.func.func_name, hc.tid, dbg.context.Eip))
	#log.i( "Arguments:")
	#for name, t in hc.func.args_list:
	#	log.i( "%s=%#x" % (name, hc.args[name]))
	#log.i( "Return address:%#x" % hc.ret_addr	)
	pass


def global_exit_hook(hc, dbg):
	
	#log.i( "[%s() returning]: Thread-%d at %#x" % (hc.func.func_name, hc.tid, dbg.context.Eip))
	#log.i( "Return value:%#x" % hc.ret_value)
	pass



class HookContext:
	"""docstring for HookContext"""

	def __init__(self, func, exit_bps):
		self.func 		= func
		self.exit_bps 	= exit_bps

		self.args 		= {}
		self.tid		= None
		self.pid		= None
		self.ret_addr	= None
		self.ret_value	= None
		self.module		= None 


	def __str__(self):
		s = "[Thread %d] - %s:\n" % (self.tid, self.func)
		s += "Arguments:\n"
		for name, t in self.func.args_list:
			s += "\t%10s - %#x\n" % (name,self.args[name])
		s += "Returned %#x at %#x\n" %(self.ret_value, self.ret_addr)
		return s

	
	def save(self, force= False):
		# Create HookInfo and save.
		info = HookInfo(self)
		info.save()

# Utilities method. Can be used in user-defined hook callback handler.

	def is_reg(self, s):
		return type(s) is str and s.lower() in ["eax","ebx","ecx","edx","eip","esp","ebp","esi","edi"]
	def is_addr(self,s):
		return type(s) is int

	def get_args(self, dbg):
		args = {}
		for arg_name, arg_type in self.func.args_list:
			if type(arg_type) is int:
				# Arguments in stack.
				args[arg_name] = dbg.get_arg(arg_type)
			elif self.is_reg(arg_type):
				# Arguments in register.
				args[arg_name] = dbg.get_register(arg_type)
		return args

	def get_value(self, s):
		# Accept register name("EAX","EBX",etc) and arguments name("buf","lpFileName")
		if self.is_reg(s):
			s = dbg.get_register(s)
		elif s in self.args:
			s = self.args[s]		
		return s 

	def read_process_memory(self, dbg, addr, length, ignore_limit = False):
		'''
		Read debuggee's memory by address and length.
		If length larger than READ_DATA_LIMIT, data will be truncated.
		'''
		if not ignore_limit and length > config.READ_DATA_LIMIT:			
			suffix = "[truncated at %d bytes..]" % config.READ_DATA_LIMIT
			return dbg.read_process_memory(addr, config.READ_DATA_LIMIT) + suffix
		else:
			return dbg.read_process_memory(addr, length)

	def read_until(self, dbg, addr, flag_bytes, step = 1, ignore_limit = False):
		'''
		Read debuggee's memory until hitting byte in flag_bytes.
		If length larger than READ_DATA_LIMIT, data will be truncated.
		'''
		buf  = ""
		offset  = 0
		while 1: 
			if not ignore_limit and offset > config.READ_DATA_LIMIT:			
				suffix = "[truncated at %d bytes..]" % config.READ_DATA_LIMIT
				return buf + suffix

			byte = dbg.read_process_memory( addr + offset, 1)
			if byte and byte not in flag_bytes:
				buf += byte
				offset  += step
				continue
			else:
				#log.d("%s-%s: read %d bytes." %(__name__, log.func(), offset ))
				break
		return buf

	def read_in(self, dbg, addr, flag_bytes, step = 1, ignore_limit = False):
		buf  = ""
		offset  = 0
		while 1: 
			if not ignore_limit and offset > config.READ_DATA_LIMIT:			
				suffix = "[truncated at %d bytes..]" % config.READ_DATA_LIMIT
				return buf + suffix

			byte = dbg.read_process_memory( addr + offset, 1)
			if byte and byte in flag_bytes:
				buf += byte
				offset  += step
				continue
			else:
				#log.d("%s-%s: read %d bytes." %(__name__, log.func(), offset ))
				break
		return buf

	def read_null_terminated_bytes(self, dbg, addr, ignore_limit = False):

		addr = self.get_value(addr)
		# addr is NULL pointer.
		if addr == 0:
			return "NULL"

		return self.read_until(dbg, addr, "\x00", ignore_limit)


	def read_string(self, dbg, addr, read_unicode=False, length= None, ignore_limit = False):
		'''
		Read string(ASCII or Unicode). NULL-terminated string or known length.
		length is Real length(bytes).
		'''
		addr = self.get_value(addr)
		# addr is NULL pointer.
		if addr == 0:
			return "NULL"

		# Length is known
		if length is not None and length %2 == 0 :
			buf = self.read_process_memory(dbg, addr, length, ignore_limit)
			if read_unicode:
				return "".join( [ buf[i*2] for i in xrange(length/2) ])
			return buf 

		
		step = 1
		if read_unicode:
			step = 2

		return self.read_in(dbg, addr, string.printable, step, ignore_limit)

	def read_string_auto(self, dbg, addr, length= None, ignore_limit = False):
		'''
		Try read ASCII and Unicode string, return the longer one.
		Really ungly, but quite useful.
		'''
		addr = self.get_value(addr)
		# addr is NULL pointer.
		if addr == 0:
			return "NULL"
					
		buf1 = self.read_string(dbg, addr, False, length, ignore_limit)
		#log.d("buf1: %s" % buf1)
		buf2 = self.read_string(dbg, addr, True,  length, ignore_limit)
		#log.d("buf2: %s" % buf2)
		buf3 = self.read_string(dbg, addr+1, True,  length, ignore_limit)
	
		result = buf1
		if len(result) < len(buf2):
			result = buf2
		if len(result) < len(buf3):
			result = buf3
		return result


	def read_data(self, dbg, addr , size, ignore_limit = False):
		addr = self.get_value(addr)
		size = self.get_value(size)
		try:
			buf = self.read_process_memory(dbg, addr, size, ignore_limit)
			return buf
		except Exception,e:
			log.e("Error in read_data(). "+ e.message)
			return "Error in read_data()" + e.message

	def read_dword(self, dbg, addr, offset= 0):
		addr = self.get_value(addr)
		offset = self.get_value(offset)
		if not self.is_addr(addr) or not self.is_addr(offset):
			return 0L
		buf = dbg.read_process_memory(addr+offset, 4)
		if not buf:
			return 0L
		return struct.unpack("<L",buf )[0]


# Callback method.
# Methods below can only be called by HookPoint

	def on_entry(self, dbg):
		# Fill context. This may be used in self.func.exit_hook().
		self.tid = dbg.dbg.dwThreadId
		self.pid = dbg.dbg.dwProcessId

		self.ret_addr = dbg.get_arg(0)
		self.args = self.get_args(dbg)

		if not self.module:
				module = dbg.addr_to_module(self.ret_addr)
				if module:
					self.module = module.szModule.lower()
				else:
					self.module = "UNKNOWN"

		# Call user-defined handler.
		if self.func.entry_hook:
			try:
				global_entry_hook(self, dbg)
				self.func.entry_hook(self, dbg)
			except Exception, e:
				log.e("Exception %s in entry_hook of %s:\n %s" %
					(e, self.func, traceback.format_exc()))

	def on_exit(self, dbg):
		# Fill context.
		self.ret_value = dbg.context.Eax

		# Save hook context to info_man.hook_infos, before calling
		# user-defined handler. 
		# This will be submited to InfoManager earlier before 
		# user-defined DbgInfo does.
		self.save()

		# Call user-defined handler.
		if self.func.exit_hook:
			try:
				global_exit_hook(self, dbg)				
				self.func.exit_hook(self, dbg)
			except Exception, e:
				log.e("Exception %s in exit_hook of %s:\n %s" %
					(e, self.func, traceback.format_exc()))

		# reduce the break count
		self.exit_bps[dbg.context.Eip] -= 1

		# if the break count is 0, remove the bp from the exit point.
		if self.exit_bps[dbg.context.Eip] == 0:
			dbg.bp_del(dbg.context.Eip)

		return DBG_CONTINUE	

