import pyfiglet
import optparse
from socket import *
from threading import *
from datetime import datetime
screenLock = Semaphore(value=1)
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print (ascii_banner)
def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		setdefaulttimeout(1)
		connSkt.connect((tgtHost, tgtPort))
		screenLock.acquire()
		print ('[+] %d/tcp open'% tgtPort)
	except:
		screenLock.acquire()
		#print ('[-] %d/tcp closed'% tgtPort)
	finally:
		screenLock.release()
		connSkt.close()
        
def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print ("[-] Cannot resolve '%s': Unknown host"%tgtHost)
		return
	try:
		print ("-" * 50)
		print ('[+] Scan Results for: ' + tgtIP)
		print ("[+] Scanning started at:" + str(datetime.now()))
		print ("-" * 50)
	except:
		print ("-" * 50)
		print ('[+] Scan Results for: ' + tgtIP)
		print ("[+] Scanning started at:" + str(datetime.now()))
		print ("-" * 50)
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
def portScanAll(tgtHost):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print ("[-] Cannot resolve '%s': Unknown host"%tgtHost)
		return
	try:
		print ("-" * 50)
		print ('[+] Scan Results for: ' + tgtIP)
		print ("[+] Scanning started at:" + str(datetime.now()))
		print ("-" * 50)
	except:
		print ("-" * 50)
		print ('[+] Scan Results for: ' + tgtIP)
		print ("[+] Scanning started at:" + str(datetime.now()))
		print ("-" * 50)
	setdefaulttimeout(1)
	for tgtPort in range(1,200):
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
def main():
	parser = optparse.OptionParser('usage%prog '+'-H <target host> -p <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	if (options.tgtPort == 'all'):
        	portScanAll(tgtHost)
	else:
		tgtPorts = str(options.tgtPort).split(',')
		if (tgtHost == None) | (tgtPorts[0] == None):
			print (parser.usage)
			exit(0)
		portScan(tgtHost, tgtPorts)
if __name__ == "__main__":
	main()
