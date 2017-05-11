from scapy.all import *
import sys

a = sniff(count=1,filter="tcp and tcp[tcpflags] == tcp-syn and src host 10.192.190.193")
packet = a[TCP][0]
src_ip = packet[IP][0].src
dst_ip = packet[IP][0].dst

print(src_ip)
print(dst_ip)

dport = packet.sport
SeqNr = packet.seq
AckNr = packet.seq + 1

ip=IP(src=dst_ip, dst=src_ip)
TCP_SYNACK=TCP(sport=a[0].dport, dport=dport, flags="SA", seq=SeqNr, ack=AckNr, options=[('MSS', 1460)])

ANSWER=sr1(ip/TCP_SYNACK)
