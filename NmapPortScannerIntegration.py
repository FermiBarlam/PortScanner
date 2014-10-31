__author__ = 'Derog'

import optparse
from socket import *
from threading import *

import nmap


screenLock = Semaphore(value=1)


def nmapScan(tgtHost, tgtPort, tgtIP):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    try:
        state = nmScan[tgtIP]['tcp'][int(tgtPort)]['state']
        screenLock.acquire()
        print("[*] " + tgtHost + " tcp/" + tgtPort + " " + state)
    except KeyError as exkey:
        screenLock.acquire()
        print("[!] Cannot scan host!: " + tgtHost + ":" + tgtPort)
    finally:
        screenLock.release()


def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve " + str(tgtHost) + ": Unknown host")
        return
    try:
        tgtName = gethostbyaddr(tgtIP)
        print("[+] Scan Results for: " + tgtName[0])
    except:
        print("[+] Scan Results for: " + tgtIP)
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=nmapScan, args=(tgtHost, str(tgtPort), tgtIP))
        t.start()


def main():
    parser = optparse.OptionParser('usage %prog -H' + '<target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type="string", help="specify target host")
    parser.add_option('-p', dest='tgtPort', type="string", help="specify target port[s] separated by comma")
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')

    if tgtHost is None or tgtPorts is None:
        print(parser.usage)
        exit(0)
    portScan(tgtHost, tgtPorts)


if __name__ == "__main__":
    main()
