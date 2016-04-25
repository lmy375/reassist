import webbrowser, cPickle, sys

import config
import log
from report import *


class __InfoManager:
	"""docstring for __InfoManager"""

	def __init__(self):
		self.pe_infos	= []
		self.dbg_infos	= []

		self.categories	= {}
		self.processes	= {}
		self.threads	= {}

		self.count		= {}

	def _count_attr(self, obj_list, attr, tag_format = "%s"):
		count = {}
		for obj in obj_list:
			if hasattr(obj, attr):
				value = getattr(obj, attr)
				tag = tag_format % value
				count[tag] = count.get(tag, 0) +1
		return count

	def _count(self, tag):
		self.count[tag] = self.count.get(tag,0) + 1

	def add_dbginfo(self,info):
		self.dbg_infos.append(info)

		# Collect tags in categories.
		if not self.categories.has_key(info.category):
			self.categories[info.category] = []

		tags = self.categories[info.category]
		if info.tag not in tags:
			tags.append(info.tag)
		
		self._count(info.tag)

		# Collect pid and tid.
		if not self.processes.has_key(info.pid):
			self.processes[info.pid] = {}
		self._count("Process%d" % info.pid)
		if not self.threads.has_key(info.tid):
			self.threads[info.tid] = {}
		self._count("Thread%d" % info.tid)

	def statistic(self):
		self.categories	= {}
		self.processes	= {}
		self.threads	= {}
		self.count		= {}
		# Readd to dbg_info list.
		tmp_list = self.dbg_infos
		self.dbg_infos = []
		for info in tmp_list:
			self.add_dbginfo(info)


	def write(self, s):
		doc = open(config.REPORT_PATH, "w")
		doc.write(s)		
		doc.close()
		#self.doc.write(s.replace("\n","<br>").replace("\t", "&nbsp;"*4).replace(" ","&nbsp;"))

	def _make_side_bar(self):
		items=""

		for cate in self.categories:			
			sub_items = ""
			tags = self.categories[cate]
			tags.sort()
			for tag in tags:
				t = check_box_h(tag, 'toggle("%s")'%tag)
				t = item_h(t + label_h(self.count[tag])) 
				sub_items += t
			sub_menu = menu_h(sub_items)
			items += item_h("<b>%s (%d)</b>" % (cate ,len(tags)) + sub_menu)

		sub_items = ""
		for process in self.processes:
			tag = "Process%d" % process
			t = check_box_h(tag, 'toggle("%s")'%tag)
			t = item_h(t+ label_h(self.count[tag])) 
			sub_items += t
		items += item_h("<b>Processes (%d)</b>" % len(self.processes) + menu_h(sub_items))

		sub_items = ""
		for thread in self.threads:
			tag = "Thread%d" % thread
			t = check_box_h(tag, 'toggle("%s")'%tag)
			t = item_h(t+ label_h(self.count[tag])) 
			sub_items += t			
		items += item_h("<b>Threads (%d)</b>" % len(self.threads) + menu_h(sub_items))

		return side_bar_h(items)

	def gen_report(self):
		log.i("Generating report...")
		print ""

		text = header_h("Debug Infomation")
		total = len(self.dbg_infos)
		count = 0
		for info in self.dbg_infos:
			text+= info.to_html()
			count+=1
			sys.stdout.write("\rProcessing %d %%..." % (count * 100 /total))
		sys.stdout.flush()

		text = report_html(self._make_side_bar(), text)

		self.write(text)

		print ""
		log.i("Report generating finished!")

	def open_report(self):
		webbrowser.open(config.REPORT_PATH)

	def dump(self):
		f = open(config.DUMP_PATH, "w")
		cPickle.dump(self, f)
		f.close()

	def load(self):
		global info_man
		f = open(config.DUMP_PATH)
		info_man = cPickle.load(f)
		f.close()

info_man = __InfoManager()

if __name__ == '__main__':
	
	info_man.load()
	info_man.gen_report()
	info_man.open_report()

