# StackAttack
A tool written in python3 to exploit simple stack-based buffer overflows.


This tool contains 8 functions to help exploit buffer overflow vulnerabilities. I created this tool to maximize time for those working on their OSCP certification. Most buffer overflow resources I've encountered are taught using python2 due to easier implementation (i.e. sending ascii data over sockets). As most of you know, python2 was sunset at the beginning of 2020 and could disappear from mainstream distros any day now. For this reason, I chose to make the leap to python3 for this tool and learn some new concepts along the way. StackAttack requires the following software to be installed on the attacker system and in the attacker's path: metasploit-framework (check your distro's repo or vist https://github.com/rapid7/metasploit-framework).

Below is a screenshot of the usage menu.

![Alt text](/screenshots/brainpan/1.png?raw=true)


# Brainpan POC

Brainpan is one of the more simple binaries available to test and learn stack-based buffer overflows. For this reason, I found it suitable to use as a walkthrough of how StackAttack functions.


**Fuzzing:**

The fuzzing module works by sending a number of bytes at the target incrementally in attempt to crash the target. The size switch determines the number of bytes sent. The increment switch determines how many additional bytes are sent until the while loop condition is met (10,000 bytes).

Here is the fuzzing module being ran against brainpan.

![Alt text](/screenshots/brainpan/2.1.png?raw=true)

![Alt text](/screenshots/brainpan/2.2.png?raw=true)


**Pattern:**

The pattern module uses msf-pattern_create to create a pattern of bytes to send in place of our "A's". After the pattern is created, the pattern is sent to the target. The size switch dictates the length of the pattern.

![Alt text](/screenshots/brainpan/3.1.png?raw=true)

![Alt text](/screenshots/brainpan/3.2.png?raw=true)


**Offset:**

The offset module uses msf-pattern_offset to find the offset using the EIP register witnessed in the debuger from running the pattern module. The size switch is used for the pattern size.

![Alt text](/screenshots/brainpan/4.png?raw=true)


**EIP Control:**

The eipcontrol module confirms the offset is correct by sending filler bytes ("A's") with 4 different valued bytes ("B's"). What we are looking for here is the "B's" landing on the EIP register. The size switch is used for our filler bytes.

![Alt text](/screenshots/brainpan/5.1.png?raw=true)

![Alt text](/screenshots/brainpan/5.2.png?raw=true)


**Bad Characters:**

The badchars module sends a list of hexadecimal characters excluding 00 as bytes to the target to determine forbidden characters. I have coded logic to allow for the removal of up to 10 forbidden characters. This should be enough for the applications being exploited by this program. The size switch is used for our filler bytes. This module is dependent on the chars.txt file located in the repo. Note: letters are case sensitive and must be capitalized i.e. x0a would be 0A. 

![Alt text](/screenshots/brainpan/5.3.png?raw=true)

![Alt text](/screenshots/brainpan/5.4.png?raw=true)


**Mona (not part of the tool but part of the process):**

Below are screenshots of running the mona module withing immunity to find our JMP ESP for exploitation. While not part of this tool, this process is important to the overall exploitation of the buffer overflow. First run "!mona modules" to discover the unsafe application. Next run "!mona find -s "\xff\xe4" -m 'unsafemodulename'" to locate our JMP ESP.

![Alt text](/screenshots/brainpan/6.1.png?raw=true)

![Alt text](/screenshots/brainpan/6.2.png?raw=true)


**JMP:**

The jmp module uses the JMP ESP address discovered using mona to test that our exploit hits the corect point. Set a break point on the JMP ESP address and run the module. Use the size switch for our filler bytes. Note: enter the JMP ESP address as hexadecimal. Instead of \xe1\xe2\xe3\xe4 you would type E1E2E3E4.

![Alt text](/screenshots/brainpan/7.1.png?raw=true)

![Alt text](/screenshots/brainpan/7.2.png?raw=true)

![Alt text](/screenshots/brainpan/7.3.png?raw=true)


**Calc:**

The calc module uses msfvenom to generate a payload that pops calc.exe on the target (Windows). The size switch is used for our filler bytes. The nops switch is used for adding a nopsled to our payload.


![Alt text](/screenshots/brainpan/8.1.png?raw=true)

![Alt text](/screenshots/brainpan/8.2.png?raw=true)


**Shell:**

The shell module uses msfvenom to generate a payload to send to our target to hopefully gain a reverse shell. The size switch is used for our filler bytes. The nops switch is is used for adding a nopsled to our payload. Follow the prompts and hit enter when your listener is ready.

![Alt text](/screenshots/brainpan/9.1.png?raw=true)

![Alt text](/screenshots/brainpan/9.2.png?raw=true)

![Alt text](/screenshots/brainpan/9.3.png?raw=true)
