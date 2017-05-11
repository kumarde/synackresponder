from scapy.all import *
import sys

def main():
    host = sys.argv[1]
    while True:
        a = sniff(count=1,filter="tcp and tcp[tcpflags] == tcp-syn and dst host " + sys.argv[1])
        packet = a[TCP][0]
        src_ip = packet[IP][0].src
        dst_ip = packet[IP][0].dst

        dport = packet.sport
        sequence = packet.seq
        ack = packet.seq + 1 

        ip = IP(src=dst_ip, dst=src_ip)
        synack = TCP(sport=a[0].dport, dport=dport, flags="SA", seq=sequence, ack=ack)

        ack = sendp(ip/synack)

if __name__ == "__main__":
    main()
