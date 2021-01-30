# StackAttack
A tool written in python3 to exploit simple stack-based buffer overflows.

### Todo



### Completed ✓
- [x] Created Todo
- [x] Remove unneeded os module import - Added in v 1.1 01/29/2021
- [x] Fix typo on line 281. \\x00\\x01 = 0102 should be \\x01\\x02 = 0102. -Added in v 1.1 01/29/2021
- [x] Remove nops variable from line 305. Previously the nops were passed to msfvenom but they are now separate. - Added in v 1.1 01/29/2021
- [x] Add additonal error handling. I.e. detect if chars.txt is missing when badchars is run. - Added in v 1.1 01/29/2021
- [x] Add color class to make stdout easier to decipher. - Added in v 1.1 01/29/2021
- [x] Add command switch to arg.parser for greater versatility. - Added in v 1.1 01/29/2021
- [x] Add function to pop calculator. - Added in v 1.1 01/29/2021
- [x] Redo readme to include demos of brainpan, dostackbufferoverflowgood, vulnserver, and slmail 5.5. - Added 01/30/2021
- [x] Add binary files for brainpan, dostackbufferoverflowgood, vulnserver, and slmail 5.5. - Added 01/30/2021
