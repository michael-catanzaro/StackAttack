#Full disclosure
I recently passed my OSCP exam and opted not to use my tool on it. Offensive Security clearly states they will not comment on disallowed tools so I didn't bother asking them. If you choose to use this on the exam, do so at your own risk!

# StackAttack
A tool written in python3 to exploit simple stack-based buffer overflows.


This tool contains 8 functions to help exploit buffer overflow vulnerabilities. I created this tool to maximize time for those working on their OSCP certification. Most buffer overflow resources I've encountered are taught using python2 due to easier implementation (i.e. sending ascii data over sockets). As most of you know, python2 was sunset at the beginning of 2020 and could disappear from mainstream distros any day now. For this reason, I chose to make the leap to python3 for this tool and learn some new concepts along the way. StackAttack requires the following software to be installed on the attacker system and in the attacker's path: metasploit-framework (check your distro's repo or vist https://github.com/rapid7/metasploit-framework).

Below is a screenshot of the usage menu.

![Alt text](/screenshots/brainpan/1.png?raw=true)


# Brainpan POC

Brainpan is one of the more simple binaries available to test and learn stack-based buffer overflows. For this reason, I found it suitable to use as a walkthrough of how StackAttack functions. Credit for brainpan binary goes to superkojiman on vulnhub ("https://www.vulnhub.com/entry/brainpan-1,51/").


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


# dostackbufferoverflowgood POC

Dostackbufferoverflowgood is a great resource for learning how to exploit stack-based buffer overflow vulnerabiltites. This POC shows the effectiveness of StackAttack against the dostackbufferoverflowgood binary. Notice that the optional command switch has been used in the following examples. Credit for the binary goes to Justin Steven ("https://github.com/justinsteven/dostackbufferoverflowgood").

**Fuzzing:**

Running the fuzzing module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/1.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/1.2.png?raw=true)


**Pattern:**

Running the pattern module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/2.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/2.2.png?raw=true)


**Offset:**

Running the offset module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/3.png?raw=true)


**EIP Control:**

Running the eipcontrol module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/4.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/4.2.png?raw=true)


**Bad Characters:**

Running the badchars module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/5.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/5.2.png?raw=true)


**Mona (not part of the tool but part of the process):**

Below are screenshots of running the mona module withing immunity to find our JMP ESP for exploitation. While not part of this tool, this process is important to the overall exploitation of the buffer overflow. First run "!mona modules" to discover the unsafe application. Next run "!mona find -s "\xff\xe4" -m 'unsafemodulename'" to locate our JMP ESP.

![Alt text](/screenshots/dostackbufferoverflowgood/6.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/6.2.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/6.3.png?raw=true)


**JMP:**

Running the jmp module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/7.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/7.2.png?raw=true)


**Calc:**

Running the calc module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/8.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/8.2.png?raw=true)


**Shell:**

Running the shell module against the dostackbufferoverflowgood binary.

![Alt text](/screenshots/dostackbufferoverflowgood/9.1.png?raw=true)

![Alt text](/screenshots/dostackbufferoverflowgood/9.2.png?raw=true)


# Vulnserver POC:

Vulnserver is another great learning resource for exploiting stack-based bufferoverflow vulnerabilities. This POC shows the effectiveness of StackAttack against the vulnserver binary. Notice that the optional command switch has been used in the following examples. Credit for the binary goes to Stephen Bradshaw ("https://github.com/stephenbradshaw/vulnserver").


**Fuzzing:**

Running the fuzzing module against the vulnserver binary. Notice for the following examples I used and unescaped quote in the command parameter. This is because the application requires both a username and password to be provided and the closing of the unescaped quotes appears as two separate inputs on the application. We attach the payload to the password input.

![Alt text](/screenshots/vulnserver/1.1.png?raw=true)

![Alt text](/screenshots/vulnserver/1.2.png?raw=true)

![Alt text](/screenshots/vulnserver/1.3.png?raw=true)

![Alt text](/screenshots/vulnserver/1.4.png?raw=true)


**Pattern:**

Running the pattern module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/2.1.png?raw=true)

![Alt text](/screenshots/vulnserver/2.2.png?raw=true)


**Offset:**

Running the offset module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/3.png?raw=true)


**EIP Control:**

Running the eipcontrol module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/4.1.png?raw=true)

![Alt text](/screenshots/vulnserver/4.2.png?raw=true)


**Bad Characters:**

Running the badchars module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/5.1.png?raw=true)

![Alt text](/screenshots/vulnserver/5.2.png?raw=true)


**Mona (not part of the tool but part of the process):**

Below are screenshots of running the mona module withing immunity to find our JMP ESP for exploitation. While not part of this tool, this process is important to the overall exploitation of the buffer overflow. First run "!mona modules" to discover the unsafe application. Next run "!mona find -s "\xff\xe4" -m 'unsafemodulename'" to locate our JMP ESP.

![Alt text](/screenshots/vulnserver/6.1.png?raw=true)

![Alt text](/screenshots/vulnserver/6.2.png?raw=true)

![Alt text](/screenshots/vulnserver/6.3.png?raw=true)


**JMP:**

Running the jmp module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/7.1.png?raw=true)

![Alt text](/screenshots/vulnserver/7.2.png?raw=true)


**Calc:**

Running the calc module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/8.1.png?raw=true)

![Alt text](/screenshots/vulnserver/8.2.png?raw=true)


**Shell:**

Running the shell module against the vulnserver binary.

![Alt text](/screenshots/vulnserver/9.1.png?raw=true)

![Alt text](/screenshots/vulnserver/9.2.png?raw=true)


# SLMail 5.5 POC

SLMAil 5.5 is an application with a discosed stack-based bufferoverflow vulnerabiltity. What separates this example from the others is this application was not coded to be intentionally vulnerable. This POC shows the effectiveness of StackAttack against the SLMAIL 5.5 application. Notice that the optional command switch has been used in the following examples. Note: I did not initially write this tool to have the capability to exploit this application. It had some interesting results but was exploitable nonetheless.


**Fuzzing:**

Running the fuzzing module against the SLMail 5.5 binary. Notice that the command used has an unescaped double quote. The application expects a username and password sent as different strings. I found that sending the unescaped double quote then closing it allowed the user and pass parameters to be read separately.

![Alt text](/screenshots/slmail%205.5/1.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/1.2.png?raw=true)


**Pattern:**

Running the pattern module against the SLMail 5.5 binary.

![Alt text](/screenshots/slmail%205.5/2.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/2.2.png?raw=true)


**Offset:**

Running the offset module against the SLMail 5.5 binary.

![Alt text](/screenshots/slmail%205.5/3.png?raw=true)


**EIP Control:**

Running the eipcontrol module against the SLMail 5.5 binary.

![Alt text](/screenshots/slmail%205.5/4.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/4.2.png?raw=true)


**Bad Characters:**

Running the badchars module against the SLMail 5.5 binary. Note: This is where things start to get a little interesting. "\x0d" is a bad character but did not need to be removed even though it was sent to the application. You can see that it does not show in the ESP dump. 

![Alt text](/screenshots/slmail%205.5/5.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/5.2.png?raw=true)

![Alt text](/screenshots/slmail%205.5/5.3.png?raw=true)

![Alt text](/screenshots/slmail%205.5/5.4.png?raw=true)


**Mona (not part of the tool but part of the process):**

Below are screenshots of running the mona module withing immunity to find our JMP ESP for exploitation. While not part of this tool, this process is important to the overall exploitation of the buffer overflow. First run "!mona modules" to discover the unsafe application. Next run "!mona find -s "\xff\xe4" -m 'unsafemodulename'" to locate our JMP ESP.

![Alt text](/screenshots/slmail%205.5/6.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/6.2.png?raw=true)

![Alt text](/screenshots/slmail%205.5/6.3.png?raw=true)


**JMP:**

Running the jmp module against the SLMail 5.5 binary.

![Alt text](/screenshots/slmail%205.5/7.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/7.2.png?raw=true)



**Shell:**

Running the shell module against the SLMail 5.5 binary. Note: Things get even weirder here. I could not get calc.exe to pop on this box. I could see the correct EIP register when sending the payload to the breakpoint but I assume the application wasn't liking some character in the payload. The shell function prints the payload used to stdout for trouble shooting these issues (look for where the payload stops and try removing the next character from the payload.). "\x04" was breaking the shell payload even though it was not detected as a bad character. I was able to gain a shell after removing it from the shell payload.

![Alt text](/screenshots/slmail%205.5/8.1.png?raw=true)

![Alt text](/screenshots/slmail%205.5/8.2.png?raw=true)


