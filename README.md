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

