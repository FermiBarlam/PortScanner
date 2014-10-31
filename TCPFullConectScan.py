__author__ = 'Derog'

import optparse
from socket import *
import socket
from threading import *

screenLock = Semaphore(value=1)


def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send("Testing\r\n")
        results = connSkt.recv(100)
        screenLock.acquire()
        print("[+] " + str(tgtPort) + "/tcp open")
        print("[+] " + str(results))
        connSkt.close()
    except:
        screenLock.acquire()
        print("[-] " + str(tgtPort) + "/tcp close")
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
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
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


