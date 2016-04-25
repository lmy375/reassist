import webbrowser, cgi

from pyh import *

import config

def report_html (side_bar, main_content):
	return '''
	<!DOCTYPE html>
	<html>
	<head>
		<title>REassist Report</title>
		<meta charset="utf-8">
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
		<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
		<link rel="stylesheet" type="text/css" href="semantic/semantic.min.css">
		<link rel="stylesheet" type="text/css" href="css/common.css">

		<script src="semantic/jquery.js"></script>
		<script src="semantic/semantic.min.js"></script>
		<script src="semantic/jquery.address.js"></script>

		<script src="js/common.js"></script>
	</head>
	<body id="report" class="pushable">
		<!-- side_bar begins -->
		%s
		<!-- side_bar ends -->

		<!-- pusher beigns -->
		<div class="pusher">
			<!-- menu begins -->
			<div class="ui fixed inverted blue menu">
			  <div class="header item">
				<div class="ui launch inverted  button ">
			        <i class="sidebar icon"></i>
			        Report
			 	</div>
			  </div>
		<!-- <div class="right menu">
				<div class="ui mobile dropdown link item" tabindex="0">
				  Menu
				  <i class="dropdown icon"></i>
				  <div class="menu" tabindex="-1">
					<a class="item">item1</a>
					<a class="item">item2</a>
				  </div>
				</div>
				<div class="ui dropdown link item" tabindex="0">
				  Courses
				  <i class="dropdown icon"></i>
				  <div class="menu transition hidden" tabindex="-1" style="">
					<a class="item">Petting</a>
					<a class="item">Feeding</a>
					<a class="item">Mind Reading</a>
				  </div>
				</div>
				<a class="item">other</a>
			   </div> -->
			</div>
			<!-- menu ends -->
			<!-- page begins-->
			<div class= "ui page">
			%s
			</div>
			<!-- page ends-->
		</div>
		<!-- pusher ends -->
	</body>
	</html>
	'''% (side_bar, main_content)


def check_box_h(label, onclick="" ):
	return '''
	<div class="ui toggle checkbox" onclick = '%s'>
		<input type="checkbox">
		<label> %s </label>
	</div>
	''' % (onclick, label)

def item_h(content):
	return '''
	<div class="item">
		%s
	</div>
	''' % content

def menu_h(content):
	return '''
	<div class="menu">
		%s
	</div>
	''' % content



def side_bar_h(content):
	return '''
	<div class="ui blue inverted vertical sidebar menu left">
	    %s
	 </div>
	''' % content

def table_h(head_list, body_list):
	t = table(cl="ui celled striped table")
	head = t << thead() << tr()
	for title in head_list:
		head += th(title)
	body = t << tbody()
	for row in body_list:
		r = body << tr()
		for item in row:
			r += td(item)
	return t.render()

def segment_h(title, content):
	return '''
	<div class="ui stacked segment">
		<a class="ui ribbon label">%s</a>
		%s
	</div>
	''' % (title, content)

def header_h(title):
	return '<h2 class="ui dividing header">%s</h2>\n'% title

def label_h(label):
	return '<span class="ui label">%s</span>' % label

def class_h(cls, content):
	return '<div class="%s"> %s </div>' % (cls, content)


def _pre_process(msg):
	msg = str(msg)
	msg = cgi.escape(msg)

	step = config.REPORT_LINE_LENGTH
	if len(msg) <= step:
		return msg
	return "\n".join(msg[i:i+step] for i in range(0,len(msg),step))

def accordion_h(title, content):
	title = _pre_process(title)
	return '''
	<div class="ui styled accordion">
	  <div class="title">
	    <i class="dropdown icon"></i>
	    %s
	  </div>
	  <div class="content">
	    %s
	  </div>
	</div>
	'''	% (title, content)

def list_h(key_value_list, cls = ""):
	item =  '''
	<div class="item">
	    <div class="content">
	      <div class="header">%s</div>
	      %s
	    </div>
	</div>
	'''
	text = ""
	for k, v in key_value_list:
		text += item % (_pre_process(k), _pre_process(v))

	text = '''
	<div class="ui divided  %s list">
		%s
	</div>
	''' % (cls,text)
	return text

def horizontal_list_h(key_value_list):
	
	return list_h(key_value_list, "horizontal")


def message_h(msg, cls=""):
	return '<div class="ui %s message">\n%s\n</div>\n' % (cls, _pre_process(msg))




if __name__ == '__main__':
	print item_h(check_box_h("DebugEvent",'$(".DebugEventButton").click()'))
	pass
