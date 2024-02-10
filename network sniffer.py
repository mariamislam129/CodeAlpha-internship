import socket
import struct
import textwrap

tap1='\t - '
tap2='\t\t - '
tap3='\t\t\t - '
tap4='\t\t\t\t - ' 

Dtap1='\t  '
Dtap2='\t\t '
Dtap3='\t\t\t '
Dtap4='\t\t\t\t '


def main():
    connection=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        Ddata,address=connection.recvfrom(65536)
        Reciever_mac,Sender_mac,protocol,data=EthernetFrame(Ddata)
        print('\nEthernet Frame:')
        print('Reciever: {},Sender: {},Protocol: {}'.format(Reciever_mac,Sender_mac,protocol))
        
        if protocol==8:
           (ver,header_length,tl,iprotocol,Sender,Reciever,data)=ipv4_packets(data)
           print(tap1 + 'IPv4 Packet: ')
           print(tap2 + 'Verstion: {} ,Header Length: {},TTL: {}'.format(ver,header_length,tl))
           print(tap2 + 'Protocol: {} ,Sender: {},Reciever: {}'.format(iprotocol,Sender,Reciever))
           
           if iprotocol==1:
                icmpType,code,checks,data=icmp_packet(data)
                print(tap1 + 'ICMP Packet:')
                print(tap2 + 'Type: {},Code: {},CheckSum: {}'.format(icmpType,code,checks))
                print(tap2 + 'Data: {}'.format(formatMulti(Dtap3, data))) 
           elif iprotocol==6:
                (sender_port,reciever_port,seq,ack,flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin,data)=tcp_packet(data)
                print(tap1 + 'TCP Segment: ')
                print(tap2 + 'Sender Port: {},Reciever Port: {}'.format(sender_port,reciever_port))
                print(tap2 + 'Sequence: {},Acknowlagement: {}'.format(seq,ack))
                print(tap2 + 'Flags:')
                print(tap3 + 'URG : {}, ACK : {}, PSH : {}, RST : {}, SYN : {}, FIN : {}'.format(flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin))
                print(tap2 + 'Data: ')
                print(formatMulti(Dtap3,data))
           elif iprotocol==17:
                (sender_port,reciever_port,size,data)=udp_packet(data)
                print(tap1 + 'UDP Segment:')
                print(tap2 + 'Sender Port: {},Reciever Port: {},Size: {}'.format(sender_port,reciever_port,size))
           else:
                print(tap2 + 'Data: {}'.format(formatMulti(Dtap2, data))) 
        else:
           print(tap2 + 'Data: {}'.format(formatMulti(Dtap1, data))) 
           
def EthernetFrame(data):
     Reciever_mac,Sender_mac,protocol=struct.unpack('! 6s 6s H',data[:14])
     return get_mac(Reciever_mac),get_mac(Sender_mac),socket.htons(protocol),data[14:]

def get_mac(bytes_address):
    bytes_string=map('{:02x}'.format,bytes_address)
    mac_address=':'.join(bytes_string).upper()
    return mac_address
    
def ipv4_packets(data):
    vheader_length=data[0]
    ver=vheader_length >> 4
    header_length=(vheader_length & 15) * 4
    tl,iprotocol,Sender,Reciever=struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return ver,header_length,tl,iprotocol,get_ipv(Sender),get_ipv(Reciever),data[header_length:]

def get_ipv(iaddress):
    ip_address='.'.join(map(str,iaddress))
    return ip_address

def tcp_packet(data):
    (sender_port,reciever_port,seq,ack,offset_flags)= struct.unpack('! H H L L H',data[:14])
    offset=(offset_flags >>12) * 4
    flagUrg=(offset_flags & 32) >> 5
    flagAck=(offset_flags & 16) >> 4
    flagPsh=(offset_flags & 8) >> 3
    flagRst=(offset_flags & 4) >> 2
    flagSyn=(offset_flags & 2) >> 1
    flagFin=offset_flags & 1
    return sender_port,reciever_port,seq,ack,flagUrg,flagAck,flagPsh,flagRst,flagSyn,flagFin,data[offset:]

def udp_packet(data):
    sender_port,reciever_port,size=struct.unpack('! H H 2x H',data[:8])
    return sender_port,reciever_port,size,data[8:]

def formatMulti(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join([r'\x{:02x}'.format(byte) for byte in string])
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

    
def icmp_packet(data):
    icmpType,code,checks=struct.unpack('! B B H',data[:4])
    return  icmpType,code,checks,data[4:]

if __name__ == "__main__":
    main()
