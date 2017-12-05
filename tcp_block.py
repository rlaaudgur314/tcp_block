from scapy.all import *
import sys

HTTP_Method = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS']
interface = 'enp0s3'
MyMAC = get_if_hwaddr(interface)
fake = "byebye\r\n"
def CheckHTTPMethod(pkt):
	if pkt[TCP].load.split()[0] in HTTP_Method:
		return True
	return False

def tcp_block(pkt):
	if(pkt[TCP].flags & 0x01 or pkt[TCP].flags & 0x04): # FIN or RST
		return
	
	Forward = Ether(src=MyMAC, dst=pkt[Ether].dst) / IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP()
	Forward[TCP].dport, Forward[TCP].sport = pkt[TCP].dport, pkt[TCP].sport
	Forward[TCP].flags = 0x04 | 0x10 # RST, ACK

	if(pkt.getlayer(Raw)):
		Forward[TCP].seq = pkt[TCP].seq + len(pkt[TCP].payload)
	else:
		Forward[TCP].seq = pkt[TCP].seq + 1
	Forward[TCP].ack = pkt[TCP].ack
	
	sendp(Forward, iface=interface) # forward RST
	
	Backward = Ether(src=MyMAC, dst=pkt[Ether].src) / IP(src=pkt[IP].dst, dst=pkt[IP].src) / TCP()
	Backward[TCP].dport, Backward[TCP].sport = pkt[TCP].sport, pkt[TCP].dport
	Backward[TCP].seq = pkt[TCP].ack
	if(pkt.getlayer(Raw)):
		Backward[TCP].ack = pkt[TCP].seq + len(pkt[TCP].payload)
	else:
		Backward[TCP].ack = pkt[TCP].seq + 1
	
	if("HTTP" in str(pkt) and CheckHTTPMethod(pkt)): # HTTP request
		print("HTTP request!")
		Backward[TCP].flags = 0x01 | 0x10 # FIN, ACK
		Backward = Backward / fake
	else:
	 	Backward[TCP].flags = 0x04 | 0x10 # RST, ACK
	
	sendp(Backward, iface=interface) # backward RST or FIN
	

if __name__ == '__main__':
	sniff(iface=interface, filter='tcp', prn=tcp_block) # filter TCP
