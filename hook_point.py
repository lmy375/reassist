from hook_context import *
import log
import config

from pydbg.defines import *

class HookPoint:
	"""
	Basic design from PaiMei/util/hooking.py
	"""
	def __init__(self, func):
		self.func 		= func
		self.address 	= func.address
		self.__active	= False
		self.exit_bps	= {}	# All HookContext shares this. {ret_addr: bp_count}

	def get_address(self, dbg):
		'''
			Resolve address of function.
			Ugly code...  
		'''
		if self.address is not None:
			return self.address
		self.address = dbg.func_resolve_debuggee(self.func.dll_name, self.func.func_name)
		if self.address is not None:
			# Update.
			self.func.address = self.address
			return self.address
		self.address = dbg.func_resolve(self.func.dll_name, self.func.func_name)
		# Update.
		self.func.address = self.address
		
		return self.address

		
	def hook(self, dbg):
		if self.__active: 
			return 
		self.address = self.get_address(dbg)
		if self.address is None or self.address == 0x0:
			log.e("[!] Fail to hook %s: invalid address %#x"%(self.func, self.address))
			return False
		try:
			dbg.bp_set(self.address, restore=True, handler=self.__proxy_on_entry)
		except Exception,e:
			log.e("[!] Fail to hook %s: %s" % (self.func,e.message))
			return False

		self.__active = True
		return True

	def unhook(self, dbg):
		if not self.__active: 
			return

		dbg.bp_del(self.address)
		for address in self.exit_bps.keys():
			self.dbg.bp_del(address)

		self.__active = False	

	def __proxy_on_entry(self, dbg):
		# Each time entry_hook breakpoint hits, instant a HookContext object
		# as "hc". hc stores arguments value, return address. 
		hc = HookContext(self.func, self.exit_bps)

		# Determine whether to skip this hookpoint.
		# If true, return without calling on_entry & on_exit
		if config.HOOK_SKIP_RULE(hc,dbg):
			return DBG_CONTINUE

		hc.on_entry(dbg)

		function_exit = dbg.get_arg(0)
		dbg.bp_set(function_exit, restore=True, handler=hc.on_exit)
		self.exit_bps[function_exit] = self.exit_bps.get(function_exit, 0) + 1

		return DBG_CONTINUE

