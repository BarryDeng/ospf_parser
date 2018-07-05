ALL:
	gcc myutil.c print-ospf.c ospf_handler.c -g -o ospf_handler -lbsd -lpcap 2>&1 | more     
