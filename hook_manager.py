import re

from hook_function import *
from hook_point import *
from info import *
import log
import config

class __HookManager:
	"""
	HookManager:
		Globally keep functions and hook points status.
		User registers new hook functions and handler to this.
	"""
	
	def __init__(self):
		self.func_list = []
		self.hook_list = []

	'''
	When keeps reference of pydbg here, system_dll.py __del__ 
	will throw exceptions.

	def init(self, dbg):		
		self.dbg = dbg
	'''

	def add_function(self, dll_name, func_name, args_list=[], address=None, entry_hook= None, exit_hook= None):
		'''
		dll_name: string
			Valid .dll file name.

		func_name: string
			Full function name. 
			Pay attention to *A/W, eg: "CreateFileA/CreateFileW" is valid, but "CreateFile" is not.

		args_list: list of tuples (name, type)
			Arguments of function. Each element of this is 2-tuple (name, type).
			"type" can be int or string, which means offset from ESP register or register.
			eg: [("SOCKET",1),("buff","EDI")] indicates 1st argument locates [ESP + 4], 2nd argument
				is passed in EDI register.
			Element without "type" will be regard as stack.
			eg: ["SOCKET", "buff"] equals [("SOCKET",1), ("buff",2)]. Useful for .dll function.
			When hook ocurrs, value of  arguments in args_list will auto filled into a HookContext instance.

		address: int 
			Address of this function.
			If this value is blank, dll_name and func_name will be used to resolve address.
			For functions not in .dll, this parameter should be set correctly.

		entry_hook:
		exit_hook:	function(hc, dbg)
			User-defined callback function. 1st parameter "hc" is a HookContext instance, which
			contains function context when hook ocurrs. HookContext also pre-define a few 
			util method for writing callback function. 2nd parameter "dbg" is a pydbg instance,
			if user want to get more information or do some advance operation, this will be used. 


		'''
		if type(func_name) is list:
			for f in func_name:
				self.add_function(dll_name, f, args_list, address, entry_hook, exit_hook)
		else:
			f = HookFunction(dll_name, func_name, args_list, address, entry_hook, exit_hook)
			self.func_list.append(f)

	def add_func(self, dll_name, func_string, entry_hook = None, exit_hook = None, AW=False, address = None):
		'''
		func_string:
			Funtion define from MSDN like this:
			HINTERNET WINAPI WinHttpOpen(
				_In_opt_  LPCWSTR pwszUserAgent,
				_In_      DWORD dwAccessType,
				_In_      LPCWSTR pwszProxyName,
				_In_      LPCWSTR pwszProxyBypass,
			_In_      DWORD dwFlags


		AW:
			True will auto attach "A" and "W" to function names.
		'''
		s= func_string
		func_name = s[:s.index('(')].split(' ')[-1]

		args_list = []
		s = s[s.index('(')+1:s.index(')')]
		for arg in s.split(','):
			name = re.split("\s+", arg.strip())[-1]

			# Sometimes MSDN format argument may start with "*",eg: "*buf" in recv()
			name = name.strip("*")		
			args_list.append(name)

		#print func_name, args_list
		if AW:
			func_name = [func_name+"A", func_name+"W"]
		
		self.add_function(dll_name, func_name,args_list,address, entry_hook, exit_hook)


	def start_hook(self, dbg):
		# Only hook function in HOOK_FUNCTION_LIST.
		for f in self.func_list:
			if f.func_name not in config.HOOK_FUNCTION_LIST:
				continue

			h = HookPoint(f)
			if h.hook(dbg):
					self.hook_list.append(h)				

		log.d("%d functions, %d hook success." % (len(self.func_list), len(self.hook_list)) )


'''
Global variable from HookManager. 
'''
hook_man = __HookManager()




#####################################################################
'''
User defines.
'''

hook_man.add_function("test.exe","TestRecursion",
	[("a1",1),("a2",2),("a3",3),("a4",4),("a5",5),("a6",6)],
	 address=0x401330)


'''
Hook SOCKET.
'''


class SocketSendEvent(EventInfo):
	def brief_info(self):
		return "Socket send %s bytes: %s " % (self.length, self.data[:50])
	def detail_info(self):
		return [("Data", self.data),
		("Size",self.length)]

def send_entry_hook(hc, dbg):
	info = SocketSendEvent(dbg.pid, dbg.tid,
		length=hc.args["len"],
		data = hc.read_data(dbg, "buf", "len"))
	info.save()
	log.i(info.brief_info(), dbg)
	#log.i( "Send content: %s" % hc.read_data(dbg,"buf", "len"))

hook_man.add_func("ws2_32.dll", 
	'''
	int send(
	  _In_  SOCKET s,
	  _In_  const char *buf,
	  _In_  int len,
	  _In_  int flags
	);
	''' ,
	send_entry_hook, None)

class WSASocketSendEvent(SocketSendEvent):
	pass

#	typedef struct __WSABUF {
#	  u_long   len;
#	  char FAR *buf;
#	} WSABUF, *LPWSABUF;


def WSASend_entry_hook(hc, dbg):
	buf_count = hc.args["dwBufferCount"]
	length = 0
	data = ""
	for i in xrange(buf_count):
		wsabuf_p = hc.args["lpBuffers"] + i*8 # sizeof(WSABUF)
		buf_size = hc.read_dword(dbg, wsabuf_p)
		buf_p = hc.read_dword(dbg, wsabuf_p+4)
		buf_data = hc.read_data(dbg, buf_p, buf_size)
		length += buf_size
		data += buf_data

	info = WSASocketSendEvent(dbg.pid, dbg.tid,
		length = length,
		data = data)
	info.save()	
	log.i(info.brief_info(), dbg)

hook_man.add_func("ws2_32.dll",
	'''
	int WSASend(
	  _In_   SOCKET s,
	  _In_   LPWSABUF lpBuffers,
	  _In_   DWORD dwBufferCount,
	  _Out_  LPDWORD lpNumberOfBytesSent,
	  _In_   DWORD dwFlags,
	  _In_   LPWSAOVERLAPPED lpOverlapped,
	  _In_   LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
	''',
	WSASend_entry_hook, None)

##############################################

class SocketRecvEvent(EventInfo):
	def brief_info(self):
		return "Socket recv %s bytes: %s" % (self.length, self.data[:50])
	def detail_info(self):
		return [("Data", self.data),
		("Size",self.length)]

def recv_exit_hook(hc, dbg):

	info = SocketRecvEvent(dbg.pid, dbg.tid,
		length=hc.ret_value,
		data = hc.read_data(dbg, "buf", hc.ret_value))
	info.save()
	log.i(info.brief_info(), dbg)
	#log.i( "Recv content: %s" % hc.read_data(dbg, "buf", "len"))

hook_man.add_func("ws2_32.dll",
	'''
	int recv(
	  _In_   SOCKET s,
	  _Out_  char *buf,
	  _In_   int len,
	  _In_   int flags
	);
	''',
	None, recv_exit_hook)

class WSASocketRecvEvent(SocketRecvEvent):
	pass

def WSARecv_exit_hook(hc, dbg):

	buf_count = hc.args["dwBufferCount"]
	length = 0
	data = ""
	for i in xrange(buf_count):
		wsabuf_p = hc.args["lpBuffers"] + i*8 # sizeof(WSABUF)
		buf_size = hc.read_dword(dbg, wsabuf_p)
		buf_p = hc.read_dword(dbg, wsabuf_p+4)
		buf_data = hc.read_data(dbg, buf_p, buf_size)
		length += buf_size
		data += buf_data

	info = WSASocketRecvEvent(dbg.pid, dbg.tid,
		length = length,
		data = data )
	info.save()

hook_man.add_func("ws2_32.dll",
	'''
	int WSARecv(
	  _In_     SOCKET s,
	  _Inout_  LPWSABUF lpBuffers,
	  _In_     DWORD dwBufferCount,
	  _Out_    LPDWORD lpNumberOfBytesRecvd,
	  _Inout_  LPDWORD lpFlags,
	  _In_     LPWSAOVERLAPPED lpOverlapped,
	  _In_     LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
	);
	''',
	None, WSARecv_exit_hook)



'''
Hook HTTP
'''

class HTTPOpenSession(EventInfo):
	def brief_info(self):
		return "HTTP Open Session."
	def detail_info(self):
		return [("User-Agent", self.user_agent),
			("Proxy", self.proxy),
			("Proxy-Bypass", self.bypass)]

def WinHttpOpen_entry_hook(hc, dbg):
	info = HTTPOpenSession(dbg.pid, dbg.tid,
		user_agent= hc.read_string_auto(dbg, "pwszUserAgent"),
		proxy = hc.read_string_auto(dbg, "pwszProxyName"),
		bypass = hc.read_string_auto(dbg, "pwszProxyBypass"))
	info.save()
	log.i(info.brief_info(), dbg)

	#log.i("user-agent:%s" % hc.read_string(dbg, "pwszUserAgent", True))
	#log.i("proxy-name:%s" % hc.read_string(dbg, "pwszProxyName", True))
	#log.i("proxy-bypass:%s" % hc.read_string(dbg, "pwszProxyBypass", True))	

hook_man.add_func("winhttp.dll", 
	'''
	HINTERNET WINAPI WinHttpOpen(
	  _In_opt_  LPCWSTR pwszUserAgent,
	  _In_      DWORD dwAccessType,
	  _In_      LPCWSTR pwszProxyName,
	  _In_      LPCWSTR pwszProxyBypass,
	  _In_      DWORD dwFlags
	);
	''',
	WinHttpOpen_entry_hook,None)

#############################################

class HTTPConnectEvent(EventInfo):
	def brief_info(self):
		return "HTTP connect to %s:%d" % (self.server, self.port)
		
def WinHttpConnect_entry_hook(hc, dbg):
	info = HTTPConnectEvent(dbg.pid, dbg.tid,
		server= hc.read_string_auto(dbg, "pswzServerName"),
		port = hc.get_value("nServerPort") )
	info.save()
	log.i(info.brief_info(), dbg)

	#log.i("IP:%s" % hc.read_data(dbg, "pswzServerName",20))
	#log.i("Port:%d" % hc.get_value("nServerPort"))

hook_man.add_func("winhttp.dll",
	'''
	HINTERNET WINAPI WinHttpConnect(
	  _In_        HINTERNET hSession,
	  _In_        LPCWSTR pswzServerName,
	  _In_        INTERNET_PORT nServerPort,
	  _Reserved_  DWORD dwReserved
	);
	''',
	WinHttpConnect_entry_hook, None)
#############################################

class HTTPOpenRequestEvent(EventInfo):
	def brief_info(self):
		return "HTTP request: %s %s" %(self.verb, self.path)
	def detail_info(self):
		return [("Verb", self.verb),
		("Path", self.path),
		("Version", self.version),
		("Referer", self.referer),
		("AcceptType", self.accept_type)]


def WinHttpOpenRequest_entry_hook(hc, dbg):
	#log.i("Verb:%s" % hc.read_string_auto(dbg,"pwszVerb"))
	#log.i("Path:%s"% hc.read_string_auto(dbg, "pwszObjectName"))
	#log.i("Version:%s"% hc.read_string_auto(dbg, "pwszVersion"))
	#log.i("Referer:%s"% hc.read_string_auto(dbg, "pwszReferrer"))
	#log.i("AcceptType:")
	offset = 0
	accept_type = []
	while 1:
		ptr = hc.read_dword(dbg,"ppwszAcceptTypes", offset)
		if ptr == 0L:
			break
		#log.i(hc.read_string_auto(dbg,ptr))
		accept_type.append(hc.read_string_auto(dbg,ptr))
		offset += 4
		pass
	accept_type = " ".join(accept_type)

	info = HTTPOpenRequestEvent(dbg.pid, dbg.tid,
		verb = hc.read_string_auto(dbg,"pwszVerb"),
		path = hc.read_string_auto(dbg, "pwszObjectName"),
		version = hc.read_string_auto(dbg, "pwszVersion"),
		referer = hc.read_string_auto(dbg, "pwszReferrer"),
		accept_type = accept_type)

	info.save()
	log.i(info.brief_info(), dbg)

hook_man.add_func("winhttp.dll",
	'''
	HINTERNET WINAPI WinHttpOpenRequest(
	  _In_  HINTERNET hConnect,
	  _In_  LPCWSTR pwszVerb,
	  _In_  LPCWSTR pwszObjectName,
	  _In_  LPCWSTR pwszVersion,
	  _In_  LPCWSTR pwszReferrer,
	  _In_  LPCWSTR *ppwszAcceptTypes,
	  _In_  DWORD dwFlags
	);
	''',
	WinHttpOpenRequest_entry_hook, None)

#############################################

class HttpSendRequestEvent(EventInfo):
	def brief_info(self):
		return "HTTP sends request with headers %s" % self.headers
	def detail_info(self):
		return [("Headers", self.headers),
			("Optionals", self.optionals)]

def WinHttpSendRequest_entry_hook(hc,dbg):
	#log.i("Headers:%s"% hc.read_string_auto(dbg, "pwszHeaders"))
	#log.i("Optionals:%s"% hc.read_string_auto(dbg, "lpOptional"))
	info = HttpSendRequestEvent(dbg.pid, dbg.tid,
		headers = hc.read_string_auto(dbg, "pwszHeaders"),
		optionals = hc.read_string_auto(dbg, "lpOptional"))
	info.save()
	log.i(info.brief_info(), dbg)


hook_man.add_func("winhttp.dll",
	'''
	BOOL WINAPI WinHttpSendRequest(
	  _In_      HINTERNET hRequest,
	  _In_opt_  LPCWSTR pwszHeaders,
	  _In_      DWORD dwHeadersLength,
	  _In_opt_  LPVOID lpOptional,
	  _In_      DWORD dwOptionalLength,
	  _In_      DWORD dwTotalLength,
	  _In_      DWORD_PTR dwContext
	);
	''',
	WinHttpSendRequest_entry_hook,None)


'''
Hook CreateFile
'''

class CreateFileEvent(EventInfo):
	def brief_info(self):
		return "Create file %s" % self.path

def CreateFile_entry_hook(hc, dbg):
	info = CreateFileEvent(dbg.pid, dbg.tid, 
		path =hc.read_string_auto(dbg, "lpFileName") )
	info.save()
	log.i(info.brief_info(), dbg)
	#log.i( "FileName: %s" % hc.read_string_auto(dbg, "lpFileName"))

hook_man.add_func("kernel32.dll", 
	'''
	HANDLE WINAPI CreateFile(
	  _In_      LPCTSTR lpFileName,
	  _In_      DWORD dwDesiredAccess,
	  _In_      DWORD dwShareMode,
	  _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	  _In_      DWORD dwCreationDisposition,
	  _In_      DWORD dwFlagsAndAttributes,
	  _In_opt_  HANDLE hTemplateFile
	);
	''',
	CreateFile_entry_hook, None, AW=True)

###################################################################

class ReadFileEvent(EventInfo):
	def brief_info(self):
		return "Read file %s bytes: %s" % (self.size, self.data[:50])
	def detail_info(self):
		return [("Data", self.data),
		("Size",self.size)]
		
def ReadFile_exit_hook(hc, dbg):
	#log.i( "File Content: %s" % hc.read_data(dbg, "lpBuffer", "nNumberOfBytesToRead"))
	#log.i( "Read return Size: %d" % hc.read_dword(dbg, "lpNumberOfBytesRead"))
	size = hc.read_dword(dbg, "lpNumberOfBytesRead")
	info = ReadFileEvent(dbg.pid, dbg.tid,
		size = size,
		data = hc.read_data(dbg, "lpBuffer", size))
	info.save()
	log.i(info.brief_info(),dbg)

	
hook_man.add_func("kernel32.dll", 
	'''
	BOOL WINAPI ReadFile(
	  _In_         HANDLE hFile,
	  _Out_        LPVOID lpBuffer,
	  _In_         DWORD nNumberOfBytesToRead,
	  _Out_opt_    LPDWORD lpNumberOfBytesRead,
	  _Inout_opt_  LPOVERLAPPED lpOverlapped
	);
	''',
	None, ReadFile_exit_hook)

##############################################################
class WriteFileEvent(ReadFileEvent):
	def brief_info(self):
		return "WriteFile file %s bytes: %s" % (self.size, self.data[:50])

def WriteFile_exit_hook(hc, dbg):
	size = hc.read_dword(dbg, "lpNumberOfBytesWritten")
	info = WriteFileEvent(dbg.pid, dbg.tid,
		size = size,
		data = hc.read_data(dbg, "lpBuffer", size))
	info.save()
	log.i(info.brief_info(),dbg)


hook_man.add_func("kernel32.dll",
	'''
	BOOL WINAPI WriteFile(
	  _In_         HANDLE hFile,
	  _In_         LPCVOID lpBuffer,
	  _In_         DWORD nNumberOfBytesToWrite,
	  _Out_opt_    LPDWORD lpNumberOfBytesWritten,
	  _Inout_opt_  LPOVERLAPPED lpOverlapped
	);
	''',
	None, WriteFile_exit_hook)



'''
Hook Process
'''
class CreateProcessEvent(EventInfo):

	def brief_info(self):
		return "Create process: %s" % self.exe
	def detail_info(self):
		return [("EXE file Name",self.exe),
			("Command Line", self.cmd),
			("Environment", self.env),
			("Current Directory", self.cur_dir)]


def CreateProcess_exit_hook(hc, dbg):
	
	info = CreateProcessEvent(dbg.pid, dbg.tid, 
		exe = hc.read_string_auto(dbg,"lpApplicationName"), 
		cmd = hc.read_string_auto(dbg, "lpCommandLine"),
		env = hc.read_string_auto(dbg, "lpEnvironment"),
		cur_dir = hc.read_string_auto(dbg, "lpCurrentDirectory"))

	info.save()
	log.i(info.brief_info(),dbg)

hook_man.add_func("kernel32.dll", 
	'''
	BOOL WINAPI CreateProcess(
	  _In_opt_     LPCTSTR lpApplicationName,
	  _Inout_opt_  LPTSTR lpCommandLine,
	  _In_opt_     LPSECURITY_ATTRIBUTES lpProcessAttributes,
	  _In_opt_     LPSECURITY_ATTRIBUTES lpThreadAttributes,
	  _In_         BOOL bInheritHandles,
	  _In_         DWORD dwCreationFlags,
	  _In_opt_     LPVOID lpEnvironment,
	  _In_opt_     LPCTSTR lpCurrentDirectory,
	  _In_         LPSTARTUPINFO lpStartupInfo,
	  _Out_        LPPROCESS_INFORMATION lpProcessInformation
	);
	''',
	None, CreateProcess_exit_hook, AW=True)


'''
Hook Register.
'''

__HKEY_CONST = {
0x80000000L:"HKEY_CLASSES_ROOT",
0x80000001L: "HKEY_CURRENT_USER",
0x80000002L: "HKEY_LOCAL_MACHINE",
0x80000003L: "HKEY_USERS",
0x80000005L: "HKEY_CURRENT_CONFIG"
}
def _h_key(key):
	return __HKEY_CONST.get(key,hex(key))


class RegOpenEvent(EventInfo):
	def brief_info(self):
		return "Register Open Key: %s =  %s\%s " %(self.out_hkey, self.h_key, self.sub_key)

def RegOpenKeyEx_exit_hook(hc, dbg):
	info = RegOpenEvent(dbg.pid, dbg.tid,
		h_key = _h_key(hc.args["hKey"]),
		sub_key = hc.read_string_auto(dbg, "lpSubKey"),
		out_hkey = hex(hc.read_dword(dbg,"phkResult")))
	info.save()
	log.i(info.brief_info(),dbg)

	#log.i("Open Key:")
	#log.i("HKEY: %#x"% hc.args["hKey"])
	#log.i("SubKey: %s" % hc.read_string_auto(dbg, "lpSubKey"))

hook_man.add_func("Advapi32.dll",
	'''
	LONG WINAPI RegOpenKeyEx(
	  _In_      HKEY hKey,
	  _In_opt_  LPCTSTR lpSubKey,
	  _In_      DWORD ulOptions,
	  _In_      REGSAM samDesired,
	  _Out_     PHKEY phkResult
	);
	''',
	None, RegOpenKeyEx_exit_hook,  AW= True)

##############################################

class RegCreateEvent(EventInfo):
	def brief_info(self):
		return "Register Create Key %s = %s\%s" % ( self.out_hkey, self.h_key, self.sub_key)
	def detail_info(self):
		return [("HKEY", self.h_key),
		("Sub Key", self.sub_key),
		("Class", self.cls)]

def RegCreateKeyEx_exit_hook(hc, dbg):

	info = RegCreateEvent(dbg.pid, dbg.tid, 
		sub_key = hc.read_string_auto(dbg, "lpSubKey"),
		h_key = _h_key(hc.args["hKey"]),
		cls = hc.read_string_auto(dbg, "lpClass"),
		out_hkey = hex(hc.read_dword(dbg,"phkResult")))
	info.save()
	log.i(info.brief_info(),dbg)

	#log.i("Create Key:")
	#log.i("HKEY: %#x" % hc.args["hKey"])
	#log.i("SubKey: %s"% hc.read_string_auto(dbg, "lpSubKey"))
	#log.i("Class: %s" % hc.read_string_auto(dbg, "lpClass"))

hook_man.add_func("Advapi32.dll",
	'''
	LONG WINAPI RegCreateKeyEx(
	  _In_        HKEY hKey,
	  _In_        LPCTSTR lpSubKey,
	  _Reserved_  DWORD Reserved,
	  _In_opt_    LPTSTR lpClass,
	  _In_        DWORD dwOptions,
	  _In_        REGSAM samDesired,
	  _In_opt_    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	  _Out_       PHKEY phkResult,
	  _Out_opt_   LPDWORD lpdwDisposition
	);
	''',
	None, RegCreateKeyEx_exit_hook, AW= True)

#########################################

class RegSetEvent(EventInfo):
	def brief_info(self):
		return "Register set Key %s = %s" % (self.name, self.data)
	def detail_info(self):
		return [("HKEY",self.h_key),
		("Name",self.name),
		("Data",self.data),
		("Size",self.size)]


def RegSetValueEx_entry_hook(hc, dbg):

	info = RegSetEvent(dbg.pid, dbg.tid,
		h_key = _h_key(hc.args["hKey"]),
		name = hc.read_string_auto(dbg, "lpValueName"),
		size = hc.args["cbData"],
		data = hc.read_string_auto(dbg, "lpData"))
	info.save()
	log.i(info.brief_info(),dbg)

	#log.i("Set Key:")
	#log.i("HKEY: %#x" % hc.args["hKey"])
	#log.i("name: %s" % hc.read_string_auto(dbg, "lpValueName"))
	#log.i("size: %d" % hc.args["cbData"])


hook_man.add_func("Advapi32.dll",
	'''
	LONG WINAPI RegSetValueEx(
	  _In_        HKEY hKey,
	  _In_opt_    LPCTSTR lpValueName,
	  _Reserved_  DWORD Reserved,
	  _In_        DWORD dwType,
	  _In_        const BYTE * lpData,
	  _In_        DWORD cbData
	);
	''',
	RegSetValueEx_entry_hook, None, AW= True)

############################################################

class RegQueryEvent(EventInfo):
	def brief_info(self):
		return "Register query Key %s = %s" % (self.name, self.data)
	def detail_info(self):
		return [("HKEY",self.h_key),
		("Name",self.name),
		("Data",self.data),
		("Size",self.size)] 

def RegQueryValueEx_exit_hook(hc, dbg):

	size = hc.read_dword(dbg, "lpcbData")
	info = RegQueryEvent(dbg.pid, dbg.tid, 
		h_key = _h_key(hc.args["hKey"]),
		name = hc.read_string_auto(dbg, "lpValueName"),
		size = size,
		data = hc.read_data(dbg,"lpData", size))
	info.save()
	log.i(info.brief_info(),dbg)

	#log.i("Query Key:")
	#log.i("HKEY: %#x" % hc.args["hKey"])
	#log.i("name: %s" % hc.read_string_auto(dbg, "lpValueName"))
	#log.i("size: %d" % hc.read_dword(dbg, "lpcbData"))

hook_man.add_func("Advapi32.dll",
	'''
	LONG WINAPI RegQueryValueEx(
	  _In_         HKEY hKey,
	  _In_opt_     LPCTSTR lpValueName,
	  _Reserved_   LPDWORD lpReserved,
	  _Out_opt_    LPDWORD lpType,
	  _Out_opt_    LPBYTE lpData,
	  _Inout_opt_  LPDWORD lpcbData
	);
	''',
	None, RegQueryValueEx_exit_hook, AW=True)


