import datetime,cgi

from info_manager import *
from utilities import *
import config
import log

class DbgInfo:
	
	def __init__(self,pid,tid,**kwargs):
		self.pid = pid
		self.tid = tid
		self.timestamp = None
		self.tag = self.__class__.__name__
		self.category = "Other Information"
		for k, v in kwargs.items():
			setattr(self, k, v)

	def prefix(self):
		return "%s <%4d:%4d> " %(self.timestamp.time(), self.pid, self.tid)

	def brief_info(self):
		return " Defalut DbgInfo\n"

	def detail_info(self):
		return []

	def render(self):
		brief = self.prefix() + self.brief_info()
		detail = self.detail_info()

		if type(detail) is list and len(detail):
			return accordion_h(brief, horizontal_list_h(detail))
		else:
			return message_h(brief)

	def save(self, force= False):
		'''
			Call this method to save infomation to "Database" 
			(we do not user real database now, but maybe true in future.)
		'''
		# To avoid save twice.
		if force or not self.timestamp:
			self.timestamp = datetime.datetime.now()
			info_man.add_dbginfo(self)
			

	# InfoManager call this to generate HTML report.
	# Sub class should not rewrite this.
	def to_html(self):
		# Add tag as CSS class.
		# Frontend can use class to hide or show this slice of message.
		cls = "DbgInfo "
		cls += self.tag 
		cls += " Process%d" % (self.pid)
		cls += " Thread%d"%(self.tid)
		return class_h(cls, convert_to_printable(self.render()))
'''
	Hook Function Information
'''
class HookInfo(DbgInfo):
	def __init__(self, hc):
		self.pid = hc.pid
		self.tid = hc.tid
		self.args = dict(hc.args)
		self.func = hc.func
		self.ret_addr = hc.ret_addr
		self.ret_value = hc.ret_value
		self.module = hc.module

		self.timestamp = None

		# Use name of hook function as tag.
		self.tag = self.func.func_name
		self.category = "Hook Functions"

# Method for infomation manager to generate HTML report.

	def brief_info(self):
		text =  " - %s[%#8x] " % (self.module, self.ret_addr)
		text += self.func.func_name+ "( "
		for name, t in self.func.args_list:
			text += "%#x, " % self.args[name]
		text = text[:-2] + ")" # eat the last ", "
		text += " = %#x " % self.ret_value
		return text

	def detail_info(self):
		return [("Function", self.func.func_name),
		("Function Address", hex(self.func.address)),
		("Module", self.module),
		("Return address", hex(self.ret_addr)),
		("Return value", hex(self.ret_value))
		] + [ (name,hex(self.args[name])) for name, t in self.func.args_list]
		


'''
	Debug Event Information.
'''
class DebugEventInfo(DbgInfo):
	def __init__(self,pid,tid,**kwargs):
		DbgInfo.__init__(self, pid, tid, **kwargs)
		self.category = "Debug Event"


class DebugStringInfo(DebugEventInfo):
	# self.debug_string
	def brief_info(self):
		return "Output debug string: %s" % self.debug_string

##################### DLL #########################
class LoadDllInfo(DebugEventInfo):
	# self.path
	def brief_info(self):
		return "Load DLL %s" % self.path

class UnloadDllInfo(DebugEventInfo):
	# self.path
	def brief_info(self):
		return "Unload DLL %s "% self.path

#################### Thread #####################		

class CreateThreadInfo(DebugEventInfo):
	def brief_info(self):
		return "Create thread %d" % self.tid
		
class ExitThreadInfo(DebugEventInfo):
	def brief_info(self):
		return "Exit thread %d" % self.tid

#################### Process ###################

class CreateProcessInfo(DebugEventInfo):
	def brief_info(self):
		return "Create process %s" % self.pid

class ExitProcessInfo(DebugEventInfo):
	def brief_info(self):
		return "Exit process %s" % self.pid


'''
Function Events Information
'''

class EventInfo(DbgInfo):
	def __init__(self,pid,tid,**kwargs):
		DbgInfo.__init__(self, pid, tid, **kwargs)
		self.category = "Events"





if __name__ == '__main__':
	d = DbgInfo(1,1)
	d.save()
	print d.to_html()
	d = LoadDllInfo(1,1,path="c:/kernel32.dll")
	d.save()
	print d.to_html()