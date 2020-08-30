# BEGINNER 🔰
### by \_5upr4
## Challenge prompt
> Dust off the cobwebs, let's reverse!
## Solution 🔮
### First steps
First of all, I ran the file command against the given file to see what I'm dealing with:
```
root@adventureBox:~/googleCTF2020/BEGINNER# file a.out 
a.out: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e3a5d8dc3eee0e960c602b9b2207150c91dc9dff, 
for GNU/Linux 3.2.0, not stripped
```
So it is an ELF binary as expected. Before doing anything else, let's run `strings` command to see if we find anything of use, and indeed we see some interesting stuff:
```
strncmp
__isoc99_scanf
puts
printf
%15s
Flag:
SUCCESS
FAILURE
CTF{
```
The most interesting is `CTF{`, which is most likely the flag format. There are some libc functions as well, but we'll get to them later.
### Getting our hands dirty
Let's run the binary to see what it does:
```
root@adventureBox:~/googleCTF2020/BEGINNER# ./a.out 
Flag: AAAAAAAAAAAAAAAAAA
FAILURE
```
Sounds like we need to input the correct flag to get that *SUCCESS* text. Interesting!\
Since the binary uses `strncmp` instead of `strcmp`, it is probably **not** vulnerable to standard buffer overflow attacks. Nevertheless, I gave it a try. And as I guessed, it wasn't. I tried some format string vulnerability testing to see if it is in fact vulnerable to this (since it uses `printf`), 
but it wasn't either.\
So let's hop it in gdb (with `gef` extension installed) and analyze it with more detail. Disassembling the `main` function, we see that 40 bytes are allocated for local variables:
```
sub    rsp,0x28
```
After this, `printf` is executed with `Flag:` as argument. Then `scanf` is called, with address to the top of the local stack frame as the second argument (pointed by `r12` register) and the string `%15s` as the first argument, suggesting the flag to be 15 characters long.
Then our input is moved inside the `xmm0` register (which is a 128 bit or 16 byte register):
```
movdqa xmm0,XMMWORD PTR [rsp]
```
Then it is put through 3 what-the-hell instructions:
```
pshufb xmm0,XMMWORD PTR [rip+0x2fa9]        # 0x4070 <SHUFFLE>
paddd  xmm0,XMMWORD PTR [rip+0x2f91]        # 0x4060 <ADD32>
pxor   xmm0,XMMWORD PTR [rip+0x2f79]        # 0x4050 <XOR>
```
After this, it is compared with our **original** input. If this comparison succeeds, the first 4 characters will be compared with `CTF{`, and if this succeeds as well, it will print `SUCCESS`.
So now we kinda have a good understanding of how the progaram works:
- First the program asks for our input.
- Then it puts our input inside `xmm0` register.
- The register goes through `pshufb` instruction.
- Then it goes through `paddd` instruction.
- Finally it goes through `pxor` instruction.
- After all the above, it is then compared with the original input.
- If the comparison succeeds, it makes sure the first 4 characters are `CTF{`. And if it is so, the flag is correct.
### Figuring out what those SIMD instructions do
From a previous college course, I was a little familiar with SIMD instructions. So when I saw those 3 instructions, I quickly realized they are SIMD instuctions.\
Going through the documentations for `pshufb` I came across this:
> PSHUFB performs in-place shuffles of bytes in the destination operand (the first operand) according to the shuffle control mask in the source operand (the second operand).

Which is admittedly not the most clear definition! Fortunately, I came across this pseudocode:
```
char a[16]; // input a
char b[16]; // input b
char r[16]; // output r

for (i=0; i < 16; i++)
   r[i] = (b[i] < 0) ? 0 : a[b[i] % 16];
```
By trying out some examples by myself, I realized how this works. It basically shuffles each byte of our input according to the `<SHUFFLE>` mask:
```
<SHUFFLE>: 02 06 07 01 05 0b 09 0e 03 0f 04 08 0a 0c 0d 00
```
So, if we consider our input as an array of 16 characters `a[16]` (with the last one being the `null` character), the resulting string after the `pshufb` instruction is like this:
``` 
INDEX:  0      1      2      3      4      5      6      7      8      9      10      11      12      13      14      15
RES:   a[2]   a[6]   a[7]   a[1]   a[5]   a[11]  a[9]   a[14]  a[3]   a[15]  a[4]    a[8]    a[10]   a[12]   a[13]   a[0]
```
The first character `a[0]` is moved to the last place, the second one `a[1]` is moved to the index 3 and so on.
The `paddd` instruction adds every 4 bytes of the first argument to the second argument, but the carry is not transfered from one 4-byte pack to the other:
```
<ADD>: ef be ad de ad de e1 fe 37 13 37 13 66 74 63 67
```
The `pxor` instruction just XORs the first argument with the second one, nothing new here:
```
<XOR>: 76 58 b4 49 8d 1a 5f 38 d4 23 f8 34 eb 86 f9 aa
```
Now you might be wondering how does the flag go through all of this, and still stays the same?\
Well, admittedly I don't know! I'd absolutely love to hear the challenge creator talk about this. But for now, let's find the flag.
### A closer look
It sounds weird at first. The flag gets shuffled, then goes through all that adding and XORing, and still is the same?! How can I possibly use this to find the flag? \
We already know the first 4 characters of the correct flag, which is `CTF{`, and we can safely assume that the last 2 characters are `}\0`, so we need to find the remaining 10 characters in between.
``` 
INDEX:  0      1      2      3      4      5      6      7      8      9      10      11      12      13      14      15
RES:   a[2]   a[6]   a[7]   a[1]   a[5]   a[11]  a[9]   a[14]  a[3]   a[15]  a[4]    a[8]    a[10]   a[12]   a[13]   a[0]
```
Looking at the shuffle table again, we can see that `a[0]` gives us the character at index *15*, `a[1]` gives the character at index *3* and so on. And we know that the resulting string will be the correct flag. So we could use the flag characters we already know to find the other ones, maybe? let's give it a try!
### Finding the flag
```
CTF{ _ _ _ _ _ _ _ _ _ _ }\0
```
We know `a[3]` is `{` (0x7B in ascii) and it will be moved to index *8*, so let's do the add-xor thing to find the index *8* character:
```
0x7B + ADD[8] = 0x7B + 0x37 = 0xB2
0xB2 ^ XOR[8] = 0xB2 ^ 0xD4 = 0x66 => flag[8] = 'f'
CTF{ _ _ _ _ f _ _ _ _ _ }\0
```
Sounds like it's working! let's continue. Now we have `a[8] = 'f'`, and this then gives us `flag[11]`:
```
0x66 + ADD[11] = 0x66 + 0x13 = 0x79
0x79 ^ XOR[11] = 0x79 ^ 0x34 = 0x4D => flag[11] = 'M'
CTF{ _ _ _ _ f _ _ M _ _ }\0
```
`a[11]` will give us `flag[5]`:
```
0x4D + ADD[5] = 0x4D + 0xDE = 0x12B
0x2B ^ XOR[5] = 0x2B ^ 0x1A = 0x31 => flag[5] = '1'
CTF{ _ 1 _ _ f _ _ M _ _ }\0
```
Here we need to be careful to keep something in mind. When we do the add operation, we have a carry, and this carry will be added to the next significant byte which is `ADD[6]` (not `ADD[4]`, since it is little-endian), hence `ADD[6] = 0xe1 + 0x1 = 0xe2`. With that taken care of, we know `a[5]` will give `flag[4]`, so let's keep going:
```
0x31 + ADD[4] = 0x31 + 0xAD = 0xDE
0xDE ^ XOR[4] = 0xDE ^ 0x8D = 0x53 => flag[4] = 'S'
CTF{ S 1 _ _ f _ _ M _ _ }\0
```
Going forward:
```
0x53 + ADD[10] = 0x53 + 0x37 = 0x8A
0x8A ^ XOR[10] = 0x8A ^ 0xF8 = 0x72 => flag[10] = 'r'
CTF{ S 1 _ _ f _ r M _ _ }\0
```
Next:
```
0x72 + ADD[12] = 0x72 + 0x66 = 0xD8
0xD8 ^ XOR[12] = 0x8A ^ 0xEB = 0x33 => flag[12] = '3'
CTF{ S 1 _ _ f _ r M 3 _ }\0
```
Next one will be index *13*:
```
0x33 + ADD[13] = 0x33 + 0x74 = 0xA7
0xA7 ^ XOR[13] = 0xA7 ^ 0x86 = 0x21 => flag[13] = '!'
CTF{ S 1 _ _ f _ r M 3 ! }\0
```
Now, `a[13]` will give us `flag[14]`, which we already know is `}`. So let's work with `}` which will give `flag[7]`:
```
0x7D + ADD[7] = 0x7D + 0xFE = 0x17B
0x7B ^ XOR[7] = 0x7B ^ 0x38 = 0x43 => flag[7] = 'C'
CTF{ S 1 _ C f _ r M 3 ! }\0
```
Here we have a carry again, but since it is for the most significant byte of a 4-byte pack, it won't be transfered to the adjacent byte (Refer to the `paddd` documentation for this one). So we don't need to worry about it. Now, `a[7]` gives `flag[2]`, which we already have. Hmmm ... looks like we hit a dead end here. But wait! We haven't done the algorithm for the `null` byte yet! Let's go forward:
```
0x0 + ADD[9] = 0x0 + 0x13 = 0x13
0x13 ^ XOR[9] = 0x13 ^ 0x23 = 0x30 => flag[9] = '0'
CTF{ S 1 _ C f 0 r M 3 ! }\0
```
Now let's get the final character! Remember that `ADD[6]` is now `0xE2` because of that carry, so with that in mind:
```
0x30 + ADD[6] = 0x30 + 0xE2 = 0x112
0x12 ^ XOR[6] = 0x12 ^ 0x5F = 0x4D => flag[6] = 'M'
CTF{ S 1 M C f 0 r M 3 ! }\0
```
If you submit this flag, it will be wrong. Why is that? Because we're not done yet. We have a carry here, which will be transferred to `ADD[7]`. So we need to recalculate `flag[7]` again with the new `ADD[7]` value:
```
a[14] + ADD[7] = 0x7D + 0xFF = 0x17C
0x7C ^ XOR[7] = 0x7C ^ 0x38 = 0x44 => flag[7] = 'D'
CTF{ S 1 M D f 0 r M 3 ! }\0
```
We submit this one, and it is correct! Whoa, that was a lot of work. But honestly, I thought the first flag was the correct one, and it took me hours to find out the bug here (that last carry), and by the time I was done, the competition had finished 2 hours earlier.
So unfortunately for me, I couldn't submit the flag. Nevertheless, I thought my efforts desereved at least a writeup.
Hopefully someone will learn something from this.\
Happy hacking! 🐱‍💻

🚩 `CTF{S1MDf0rM3!}`

## References
- [PSHUFB documentation](https://www.felixcloutier.com/x86/pshufb#:~:text=PSHUFB%20performs%20in%2Dplace%20shuffles,leaving%20the%20shuffle%20mask%20unaffected.)
- [PSHUFB pseudocode](https://www.chessprogramming.org/SSSE3)
- [PADDD documentation](https://www.felixcloutier.com/x86/paddb:paddw:paddd:paddq)
- [PXOR documentation](https://www.felixcloutier.com/x86/pxor)





