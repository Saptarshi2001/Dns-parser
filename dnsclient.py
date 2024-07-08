import socket
import dnslib
import socket
import sys
def send_dns_query(domain=sys.argv[1], server_address=('127.0.0.1', 53)):
    
    query = dnslib.DNSRecord.question(domain)
    
    
    query_data = query.pack()
   # print(query_data.decode('utf-8'))
    
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    
    sock.sendto(query_data, server_address)
    

    sock.close()

# Example usage
if __name__=='__main__':

    send_dns_query(sys.argv[1])

