
import log

class HookFunction:
	"""Abstraction of Windows API. """

	def __init__(self, dll_name, func_name, args_list=[],address=None, entry_hook=None, exit_hook= None):
		self.dll_name 	= dll_name
		self.func_name 	= func_name
		self.args_list 	= []		#[(arg_name, arg_type)]		arg_type: 1,2,3 for argument in stack. "eax","ebx"... for register
		
		# auto fill offset value for stack parameter.
		esp_offset 		= 1
		for i in(args_list):
			if type(i) is str:
				self.args_list.append((i,esp_offset))
				esp_offset += 1
			else:
				self.args_list.append(i)

		self.args_num = len(args_list)

		self.address = address
		self.entry_hook = entry_hook
		self.exit_hook = exit_hook

	def __str__(self):
		s = "%s.%s()" % (self.dll_name, self.func_name)
		if self.address is not None:
			s += "[%#x]" % self.address
		return s

if __name__ == '__main__':
	pass



		