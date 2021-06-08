#!/usr/bin/env python3
import sys
from scapy.all import *
import csv

ports_tcp = [1,5,7,9,11,13,17,18,19,20,21,22,23,25,37,39,42,43,49,50,53,70,71,79,80,81,88,101,102,105,107,109,110,111,115,117,119,137,138,139,143,162,177,179,194,199,201,209,210,213,220,369,370,389,427,443,444,445,464,512,513,514,515,520,530,531,532,540,543,544,546,547,548,554,556,563,587,631,631,636,674,694,749,873,992,993,995]
ports_udp = [1,5,7,9,11,13,17,18,19,21,22,37,39,42,49,50,53,67,68,69,82,88,105,111,113,123,137,138,139,143,161,162,177,194,199,201,209,210,213,220,369,370,389,427,444,464,500,512,513,514,517,518,520,521,525,530,531,533,546,547,554,563,631,631,636,694,749,750,992]
ip_experimento = sys.argv[1]


def TCPScanner(port,ip,csv):
    abiertos_tcp = 0
    filtrados_tcp = 0
    cerrados_tcp = 0
    portsAbiertos = []
    for i in ports_tcp:
        p = IP(dst=ip)/TCP(dport=i, flags='S')
        #print(i ,end='')
        
        resp = sr1(p, verbose=False, timeout=1.0)
        if resp is None:
            #print(" filtrado")
            filtrados_tcp += 1
        elif resp.haslayer(TCP):
            tcp_layer = resp.getlayer(TCP)
            
            if tcp_layer.flags == 0x12:
                #print(" abierto", tcp_layer.flags)
                sr1(IP(dst=ip)/TCP(dport=ports_tcp, flags='AR'), verbose=False, timeout=1)
                abiertos_tcp += 1
                portsAbiertos.append(i)
            elif tcp_layer.flags == 0x14:
                #print(" cerrado", tcp_layer.flags)
                cerrados_tcp += 1
    print("TCP : filtrados = %i, abiertos = %i, cerrados = %i" % (filtrados_tcp, abiertos_tcp, cerrados_tcp))
    resultados = ['tcp',abiertos_tcp,cerrados_tcp,filtrados_tcp]
    csv.writerow(resultados)
    print("Los puertos abiertos son", portsAbiertos)

    


def UDPScanner(port,ip,csv):
    abiertos_udp = 0
    filtrados_udp = 0
    cerrados_udp = 0
    portsAbiertos = []
    for i in ports_udp:
        p = IP(dst=ip)/UDP(dport=i)
        resp = sr1(p, verbose=False, timeout=1.0)
        if resp is None:
            filtrados_udp += 1
        elif(resp.haslayer(UDP)):
            abiertos_udp+=1
            portsAbiertos.append(i)
        elif(resp.haslayer(ICMP)):
            if (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) == 3):
                cerrados_udp+=1
            elif (int(resp.getlayer(ICMP).type) == 3 and int(resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
                filtrados_udp+=1
    print("UDP : filtrados = %i, abiertos = %i, cerrados = %i" % (filtrados_udp, abiertos_udp, cerrados_udp))
    resultados = ['udp',abiertos_udp,cerrados_udp,filtrados_udp]
    csv.writerow(resultados)
    print("Los puertos abiertos son", portsAbiertos)

scannedfile = open('scanned-responses-' + ip_experimento + '.csv', 'a')
writer = csv.writer(scannedfile)
writer.writerow(['protocolo','abierto','cerrado','protegido'])
UDPScanner(ports_udp,ip_experimento,writer)
TCPScanner(ports_tcp,ip_experimento,writer)
