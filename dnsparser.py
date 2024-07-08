import socket

import dns.message
import dns.rdatatype
import sys
import struct

class dnsparser:
    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port

    def get_data(self):
        
        sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        sock.bind((self.hostname, self.port))
        print("Socket listening at port "+f"{self.port}")
        data,addr=sock.recvfrom(2024)
        print(data)
        sock.settimeout(10)
            
        hex_data = data.hex()
        sock.close()

        return hex_data

    def parsedecimal(self,hexdata):
        if sys.argv[1] == "-dec":
            if sys.argv[2] == "-id":
                id_hex = hexdata[0:4]
                id_int = int(id_hex, 16)
                
                print(f"ID in decimal: {id_int}")

            elif sys.argv[2] == "-flags":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                
                print(f"Flags in decimal: {flags_int}")

            elif sys.argv[2] == "-qr":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"QR flags in decimal: {flags_int}")

            elif sys.argv[2] == "-opcode":
            
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"Opcode in decimal: {flags_int}")

            elif sys.argv[2] == "-aa":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"AA flags in decimal: {flags_int}")

            elif sys.argv[2] == "-tc":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"TC flags in decimal: {flags_int}")

            elif sys.argv[2] == "-rd":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"RD flags in decimal: {flags_int}")

            elif sys.argv[2] == "-ra":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"RA flags in decimal: {flags_int}")

            elif sys.argv[2] == "-z":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"Z flags in decimal: {flags_int}")

            elif sys.argv[2] == "-rcode":
                flags_hex = hexdata[4:8]
                flags_int = int(flags_hex, 16)
                print(f"RCODE in decimal: {flags_int}")

            elif sys.argv[2] == "-qdcount":
                qdcount_hex = hexdata[8:12]
                qdcount_int = int(qdcount_hex, 16)
                
                print(f"QDCOUNT in decimal: {qdcount_int}")

            elif sys.argv[2] == "-ancount":
                ancount_hex = hexdata[12:16]
                ancount_int = int(ancount_hex, 16)
                
                print(f"ANCOUNT in decimal: {ancount_int}")

            elif sys.argv[2] == "-nscount":
                nscount_hex = hexdata[16:20]
                nscount_int = int(nscount_hex, 16)
                
                print(f"NSCOUNT in decimal: {nscount_int}")

            elif sys.argv[2] == "-arcount":
                arcount_hex = hexdata[20:24]
                arcount_int = int(arcount_hex, 16)
                
                print(f"ARCOUNT in decimal: {arcount_int}")

            elif sys.argv[2] == "-qname":
                qname_hex=hexdata[24:(len(hexdata)-(4+4))]
                qname_int=int(qname_hex,16)
                print(f"QNAME in decimal: {qname_int}")

            elif sys.argv[2] == "-qtype":
                qtype_hex = hexdata[len(hexdata)-8:len(hexdata)-4]
                qtype_int = int(qtype_hex, 16)
                
                print(f"QTYPE in decimal: {qtype_int}")

            elif sys.argv[2] == "-qclass":
                qclass_hex = hexdata[len(hexdata)-4:]
                qclass_int = int(qclass_hex, 16)
                
                print(f"QCLASS in decimal: {qclass_int}")

    def parsebinary(self, hexdata):
        if sys.argv[1] == "-binary":
            if sys.argv[2] == "-id":
                id = hexdata[0:4]
                

                print("id in binary" + "-  " + bin(int(id, 16))[2:].zfill(16))

            if sys.argv[2] == "-flags":
                flag = hexdata[4:8]
                print("flags in binary:- ")
                print(bin(int(flag, 16))[2:].zfill(16))

            if sys.argv[2] == "-qr":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                qr = (intflags >> 15) & 1
                print("qr in binary" + "-  " + bin(qr)[2:].zfill(1))

            if sys.argv[2] == "-opcode":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                opcode = (intflags >> 11) & 0xF
                print("opcode in binary" + "-  " + bin(opcode)[2:].zfill(4))

            if sys.argv[2] == "-aa":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                aa = (intflags >> 10) & 1
                print("aa in binary" + "-  " + bin(aa)[2:].zfill(1))

            if sys.argv[2] == "-tc":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                tc = (intflags >> 9) & 1
                print("opcode in binary" + "-  " + bin(tc)[2:].zfill(1))

            if sys.argv[2] == "-rd":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                rd = (intflags >> 8) & 1
                print("opcode in binary" + "-  " + bin(rd)[2:].zfill(1))

            if sys.argv[2] == "-ra":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                ra = (intflags >> 7) & 1
                print("opcode in binary" + "-  " + bin(ra)[2:].zfill(1))

            if sys.argv[2] == "-z":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                z = (intflags >> 4) & 0x7
                print("opcode in binary" + "-  " + bin(z)[2:].zfill(3))

            if sys.argv[2] == "-rcode":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                rcode = intflags & 0xF
                print("opcode in binary" + "-  " + bin(rcode)[2:].zfill(4))

            if sys.argv[2] == "-qdcount":
                qdcount = hexdata[8:12]
                print("qdcount in binary" + "-  " + bin(int(qdcount, 16))[2:].zfill(4))

            if sys.argv[2] == "-ancount":
                ancount = hexdata[12:16]

                print("ancount in binary" + "-  " + bin(int(ancount, 16))[2:].zfill(4))

            if sys.argv[2] == "-nscount":
                nscount = hexdata[16:20]
                print(nscount)
                print("nscount in binary" + "-  " + bin(int(nscount, 16))[2:].zfill(4))

            if sys.argv[2] == "-arcount":
                arcount = hexdata[20:24]
                print("arcount in binary" + "-  " + bin(int(arcount, 16))[2:].zfill(4))

            if sys.argv[2] == "-qname":
                qname=hexdata[24:(len(hexdata)-(4+4))]

                print("qname in binary" + "-  " + bin(int(qname, 16))[2:].zfill(24))

            if sys.argv[2] == "-qtype":
                qtype = hexdata[len(hexdata)-8:len(hexdata)-4]

                print("qtype in binary" + "-  " + bin(int(qtype, 16))[2:].zfill(4))

            if sys.argv[2] == "-qclass":
                qclass = hexdata[len(hexdata)-4:]

                print("qclass in binary" + "-  " + bin(int(qclass, 16))[2:].zfill(4))

    def parsehex(self, hexdata):
        if sys.argv[1] == "-hex":
            if sys.argv[2] == "-id":
                id = hexdata[0:4]

                print("id in hex" + "-  " + id)

            if sys.argv[2] == "-flags":
                flag = hexdata[4:8]
                print("flags in hex:- ")
                print(flag)

            if sys.argv[2] == "-qr":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                qr = (intflags >> 15) & 1
                print("qr in hex" + "-  " + hex(qr).zfill(1))

            if sys.argv[2] == "-opcode":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                opcode = (intflags >> 11) & 0xF
                print("opcode in hex" + "-  " + hex(opcode).zfill(4))

            if sys.argv[2] == "-aa":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                aa = (intflags >> 10) & 1
                print("aa in hex" + "-  " + hex(aa).zfill(1))

            if sys.argv[2] == "-tc":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                tc = (intflags >> 9) & 1
                print("tc in hex" + "-  " + hex(tc).zfill(1))

            if sys.argv[2] == "-rd":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                rd = (intflags >> 8) & 1
                print("rd in hex" + "-  " + hex(rd).zfill(1))

            if sys.argv[2] == "-ra":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                ra = (intflags >> 7) & 1
                print("ra in hex" + "-  " + hex(ra).zfill(1))

            if sys.argv[2] == "-z":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                z = (intflags >> 4) & 0x7
                print("z in hex" + "-  " + hex(z).zfill(3))

            if sys.argv[2] == "-rcode":
                flags = hexdata[4:8]
                intflags = int(flags, 16)
                rcode = intflags & 0xF
                print("rcode in hex" + "-  " + hex(rcode).zfill(4))

            if sys.argv[2] == "-qdcount":
                qdcount = hexdata[8:12]
                print("qdcount in hex" + "-  " + hex(qdcount))

            if sys.argv[2] == "-ancount":
                ancount = hexdata[12:16]

                print("ancount in hex" + "-  " + hex(ancount))

            if sys.argv[2] == "-nscount":
                nscount = hexdata[16:20]
                print(nscount)
                print("nscount in hex" + "-  " + hex(nscount))

            if sys.argv[2] == "-arcount":
                arcount = hexdata[20:24]
                print("arcount in hex" + "-  " + hex(arcount))

            if sys.argv[2] == "-qname":
                qname=hexdata[24:(len(hexdata)-(4+4))]

                print("qname in hex" + "-  " + hex(qname))

            if sys.argv[2] == "-qtype":
                qtype = hexdata[len(hexdata)-8:len(hexdata)-4]

                print("qtype in hex" + "-  " + hex(qtype))

            if sys.argv[2] == "-qclass":
                qclass = hexdata[len(hexdata)-4:]

                print("qclass in hex" + "-  " + hex(qclass))

    def verticalbinary(self, hexdata):
        flags = hexdata[4:8]
        qrflags = int(flags, 16)
        qr = (qrflags >> 15) & 1
        opcodeflags = int(flags, 16)
        opcode = (opcodeflags >> 11) & 0xF
        aaflags = int(flags, 16)
        aa = (aaflags >> 10) & 1
        tcflags = int(flags, 16)
        tc = (tcflags >> 9) & 1
        rdflags = int(flags, 16)
        rd = (rdflags >> 8) & 1
        raflags = int(flags, 16)
        ra = (raflags >> 7) & 1
        zflags = int(flags, 16)
        z = (zflags >> 4) & 0x7
        rcodeflags = int(flags, 16)
        rcode = rcodeflags & 0xF
        if sys.argv[1] == "-vertical" and sys.argv[2] == "-binary":
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print("|" + "           " + bin(int(hexdata[0:4], 16))[2:].zfill(4) + " |")
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|"
                + bin(qr)[2:].zfill(1)
                + "|"
                + bin(opcode)[2:].zfill(4)
                + "|"
                + bin(aa)[2:].zfill(1)
                + "|"
                + bin(tc)[2:].zfill(1)
                + "|"
                + bin(rd)[2:].zfill(1)
                + "|"
                + bin(ra)[2:].zfill(1)
                + "|"
                + bin(z)[2:].zfill(3)
                + "|"
                + bin(rcode)[2:].zfill(4)
                + "|"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print("|" + "           " + bin(int(hexdata[8:12], 16))[2:].zfill(4) + " |")
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[12:16], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[16:20], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[20:24], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[24:(len(hexdata)-(4+4))], 16))[2:].zfill(24) + " |"
            )
            
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[len(hexdata)-8:len(hexdata)-4], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + bin(int(hexdata[len(hexdata)-4:], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")

    def verticalhex(self, hexdata):
        flags = hexdata[4:8]
        qrflags = int(flags, 16)
        qr = (qrflags >> 15) & 1
        opcodeflags = int(flags, 16)
        opcode = (opcodeflags >> 11) & 0xF
        aaflags = int(flags, 16)
        aa = (aaflags >> 10) & 1
        tcflags = int(flags, 16)
        tc = (tcflags >> 9) & 1
        rdflags = int(flags, 16)
        rd = (rdflags >> 8) & 1
        raflags = int(flags, 16)
        ra = (raflags >> 7) & 1
        zflags = int(flags, 16)
        z = (zflags >> 4) & 0x7
        rcodeflags = int(flags, 16)
        rcode = rcodeflags & 0xF
        if sys.argv[1] == "-vertical" and sys.argv[2] == "-hex":
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print("|" + "           " + hex(int(hexdata[0:4], 16))[2:].zfill(4) + " |")
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|"
                + hex(qr)[2:].zfill(1)
                + "|"
                + hex(opcode)[2:].zfill(4)
                + "|"
                + hex(aa)[2:].zfill(1)
                + "|"
                + hex(tc)[2:].zfill(1)
                + "|"
                + hex(rd)[2:].zfill(1)
                + "|"
                + hex(ra)[2:].zfill(1)
                + "|"
                + hex(z)[2:].zfill(3)
                + "|"
                + hex(rcode)[2:].zfill(4)
                + "|"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print("|" + "           " + hex(int(hexdata[8:12], 16))[2:].zfill(4) + " |")
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[12:16], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[16:20], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[20:24], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[24:(len(hexdata)-(4+4))], 16))[2:].zfill(24) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[len(hexdata)-8:len(hexdata)-4], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")
            print(
                "|" + "           " + hex(int(hexdata[len(hexdata)-4:], 16))[2:].zfill(4) + " |"
            )
            print("+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+")

    

    def binaryall(self, hexdata):
        if sys.argv[1] == "-all" and sys.argv[2] == "-binary":
            flags = hexdata[4:8]
            qrflags = int(flags, 16)
            qr = (qrflags >> 15) & 1
            opcodeflags = int(flags, 16)
            opcode = (opcodeflags >> 11) & 0xF
            aaflags = int(flags, 16)
            aa = (aaflags >> 10) & 1
            tcflags = int(flags, 16)
            tc = (tcflags >> 9) & 1
            rdflags = int(flags, 16)
            rd = (rdflags >> 8) & 1
            raflags = int(flags, 16)
            ra = (raflags >> 7) & 1
            zflags = int(flags, 16)
            z = (zflags >> 4) & 0x7
            rcodeflags = int(flags, 16)
            rcode = rcodeflags & 0xF
            qname = bin(int(hexdata[24:(len(hexdata)-(4+4))], 16))[2:].zfill(24)
            qtype = bin(int(hexdata[len(hexdata)-8:len(hexdata)-4], 16))[2:].zfill(4)
            qclass = bin(int(hexdata[len(hexdata)-4:], 16))[2:].zfill(4)
            print("The query in binary format  is:- ")
            print(f'id:{hexdata[0:4]},qr: {qr}, opcode: {opcode}, aa: {aa}, tc: {tc}, rd: {rd}, ra: {ra}, z: {z}, rcode: {rcode},qname: {qname}, qtype: {qtype}, qclass: {qclass}')

    def hexall(self, hexdata):
        if sys.argv[1] == "-all" and sys.argv[2] == "-dec":
            flags = hex(hexdata[4:8])
            qr = int(flags, 16)
            opcode = int(flags, 16)
            aa = int(flags, 16)
            tc = int(flags, 16)
            rd = int(flags, 16)
            ra = int(flags, 16)
            z = int(flags, 16)
            rcode = int(flags, 16)
            qname = int(hexdata[24:(len(hexdata)-(4+4))], 16)[2:]
            qtype = int(hexdata[len(hexdata)-8:len(hexdata)-4], 16)[2:]
            qclass = int(hexdata[len(hexdata)-4:], 16)[2:]
            print("The query in binary format  is:- ")
            print(f'id:{hex(hexdata[0:4],16)},qr: {hex(qr)}, opcode: {hex(opcode)}, aa: {hex(aa)}, tc: {hex(tc)}, rd: {hex(rd)}, ra: {hex(ra)}, z: {hex(z)}, rcode: {hex(rcode)}, qname: {qname}, qtype: {qtype}, qclass: {qclass}')
            

    def decall(self, hexdata):
        if sys.argv[1] == "-all" and sys.argv[2] == "-dec":
            flags = hexdata[4:8]
            qrflags = int(flags, 16)
            opcodeflags = int(flags, 16)
            aaflags = int(flags, 16)
            tcflags = int(flags, 16)
            rdflags = int(flags, 16)
            raflags = int(flags, 16)
            zflags = int(flags, 16)
            rcodeflags = int(flags, 16)
            qname = int(hexdata[24:(len(hexdata)-(4+4))], 16)[2:].zfill(24)
            qtype = int(hexdata[len(hexdata)-8:len(hexdata)-4], 16)[2:].zfill(4)
            qclass = int(hexdata[len(hexdata)-4:], 16)[2:].zfill(4)
            print("The query in binary format  is:- ")
            print(f'id:{int(hexdata[0:4],16)},qr: {qrflags}, opcode: {opcodeflags}, aa: {aaflags}, tc: {tcflags}, rd: {rdflags}, ra: {raflags}, z: {zflags}, rcode: {rcodeflags}, qname: {qname}, qtype: {qtype}, qclass: {qclass}')
            

    def getqname(self,hexdata):
        qname=hexdata[24:(len(hexdata)-(4+4))]
        bytehex=bytes.fromhex(qname)
        strqname=bytehex.decode('utf-8',errors='ignore')
        print(strqname)
        


if __name__ == "__main__":
    hostname = "127.0.0.1"
    port = 53
    parser = dnsparser(hostname, port)
    hexdata = parser.get_data()
    
    if sys.argv[1] == "-binary":
        parser.parsebinary(hexdata)
    elif sys.argv[1] == "-hex":
        parser.parsehex(hexdata)
    elif sys.argv[1] == "-dec":
        parser.parsedecimal(hexdata)

    elif sys.argv[1] == "-vertical" and sys.argv[2] == "-binary":
        parser.verticalbinary(hexdata)

    elif sys.argv[1] == "-vertical" and sys.argv[2] == "-hex":
        parser.verticalhex(hexdata)

    

    elif sys.argv[1] == "-all" and sys.argv[2] == "-binary":
        parser.binaryall(hexdata)

    elif sys.argv[1] == "-all" and sys.argv[2] == "-hex":
        parser.hexall(hexdata)

    elif sys.argv[1] == "-all" and sys.argv[2] == "-str":
        parser.decall(hexdata)
    
    elif sys.argv[1] == "-qname":
        parser.getqname(hexdata)



