import inspect,string

import config

def func():
    return inspect.stack()[1][3]

def convert_char(char):
	if char in string.ascii_letters or char in string.digits or char in string.punctuation or char in string.whitespace:
		return char
	else:
		if config.REPORT_PRINT_DOT:
			if char == "\x00":
				return ""
			return "."
		return r'\x%02x' % ord(char)
				
def convert_to_printable(s):
	return ''.join([convert_char(c) for c in s])


def cut(data, length=0):
	if not length:
		length = config.LOG_MSG_LENGTH
	if len(data) > length :
		data = data[:length] + "[truncate at %d bytes..]" % length
	return data