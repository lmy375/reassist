
from report import *

EXE_PATH = r"E:\work\psiphon3_old.exe"
EXE_CMD = None

# File Path
REPORT_PATH = r"report/index.html"
DUMP_PATH = r"report/info_man.dump"
LOG_PATH = r"log/"

# Max size reading process memory.
# Default 1K bytes
READ_DATA_LIMIT = 1024

# Max length of log message
LOG_MSG_LENGTH = 1000

# Text line length in HTML report
REPORT_LINE_LENGTH = 100
REPORT_PRINT_DOT = True


'''
For HookManager
'''
# Only functions in this list will be hook.
HOOK_FUNCTION_LIST = []
HOOK_FUNCTION_LIST += ["send","recv", "WSASend", "WSARecv"]
HOOK_FUNCTION_LIST += ["CreateFileA","CreateFileW", "ReadFile", "WriteFile"]
HOOK_FUNCTION_LIST += ["WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest"]
HOOK_FUNCTION_LIST += ["CreateProcessW", "CreateProcessA"]
HOOK_FUNCTION_LIST += ["RegSetValueExA" ,"RegOpenKeyExA", "RegQueryValueExA", "RegCreateKeyExA",
						"RegSetValueExW" ,"RegOpenKeyExW", "RegQueryValueExW", "RegCreateKeyExW"]

HOOK_NO_SKIP = False

HOOK_SKIP_DLL_BLACK_LIST = ["kernel32.dll"]
HOOK_SKIP_FUNC_DLL_BLACK_LIST = []
HOOK_SKIP_DLL_WHITE_LIST = ["chrome.dll"]
HOOK_SKIP_FUNC_DLL_WHITE_LIST = [("send","wsock32.dll"),("recv","wsock32.dll")]

HOOK_SKIP_ALL_DLL = True

def HOOK_SKIP_RULE(hc, dbg):
	'''
	 Hookpoint which satisfies this(returns True) will skip hook operation.
	'''
	if HOOK_NO_SKIP:
		return False
	# hc.addr is not set now. We have to do this ourselves.
	ret_addr = dbg.get_arg(0)
	module = dbg.addr_to_module(ret_addr)
	if module is None:
		# Mostly we break into wrong address.
		# So skip.
		return True
	
	hc.module = module.szModule.lower()

	if hc.module in HOOK_SKIP_DLL_BLACK_LIST:
		return True
	if hc.module in HOOK_SKIP_DLL_WHITE_LIST:
		return False

	if (hc.func.func_name, hc.module) in HOOK_SKIP_FUNC_DLL_BLACK_LIST:
		return True
	if (hc.func.func_name, hc.module) in HOOK_SKIP_FUNC_DLL_WHITE_LIST:
		return False

	#print module_name


	if HOOK_SKIP_ALL_DLL:
		return hc.module.endswith(".dll")
	return False




