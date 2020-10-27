# EzWin Writeup

Going through the code, we can see that the functionalities of the program are pretty straight forward. It allows creating/editing/filtering and printing notes. Delving deeper into the code, we observe that there is a dangling pointer created when invoking the note filtering functionality.
Before going to the actual exploitation of this issue, let's take a look at the structures involved in the dynamic allocations of the challenge:

Note:

|   00   |   vptr    |    content    |
| :----: | :-------: | :-----------: |
| **10** | **epoch** | **refNumber** |



string when len(str)<=15:

|   00   |    data     |     data      |
| :----: | :---------: | :-----------: |
| **10** | **dataLen** | **allocSize** |



string when len(str)>15:

|   00   |   dataPtr   |    unused     |
| :----: | :---------: | :-----------: |
| **10** | **datalen** | **allocSize** |



vector:

|   00   |  vectorUserBegin   | vectorUserEnd |
| :----: | :----------------: | :-----------: |
| **10** | **vectorAllocEnd** |       -       |



An overview of their sizes:

| Class         | Size                             |
| ------------- | -------------------------------- |
| Note          | 0x20                             |
| string        | 0x20                             |
| string's data | user controlled                  |
| vector        | 0x18                             |
| vector's list | predictable/partially controlled |




Looking at the table above, we can see that most of the dynamically allocated objects can have the same size and thus it should be relatively easy to allocate one object into another after the latter has been freed within both frontend and backend heap allocations.

The question now becomes, how can we use that capability to gain code execution?
Before getting into that, let's have a look at the approach that we will use to have an object allocated in a location previously occupied by another object:

1. Allocate an object of ClassA 
2. Free the object allocated in (1)
3. Repeatedly allocate objects of ClassB until we manage to have one allocated to the memory previously occupied by A in (1)

More like a bruteforce approach, but it works reliably across different versions of Windows. In the comments below there are some potentially more precise ways to do it.

Now to the actual exploitation phase, we will use three different combinations of ClassA/ClassB objects described above, each providing different capabilities and when combined allow us to get the flag.



**UAF 1: Leaking the module's base address and establishing arbitrary write primitive**

Based on the approach we defined earlier, we have:
class A: Note's 1 string (i.e. content)
class B: Note 2

Leaking the module's base address:
After successfully allocating Note 2 into the Note's 1 string, we can leak `vptr[0]` of the Note by printing Note 1 which we use to calculate the base address of the module. (constant offset in the `.text` section)

Arbitrary Write:
For the arbitrary write we will utilise the fact that we can directly manipulate the fields of the string in Note 1 by editing Note 2. 
Going through the challenge, we see that the Edit functionality offers two modes for editing the notes, prepend and append mode. Here we will use the append function' implemented on strings which works more or less like this:

```c
if (allocSize>=datalen+len(new_data)){
    memcpy(dataPtr+dataLen, new_data, len(new_data))
}
```

As we can see through the code above, with knowledge of the `dataPtr` and control over the `dataLen` it should be possible to write data to arbitrary addresses. As it turns out, we can satisfy both conditions. The `dataPtr`, after the UAF, will end up having the `vtable` address of the Note class. That address points in the `.rdata` section, at a constant offset from the module's base address which we already know. For the `dataLen`, all we have to do is modify Note's 2 `epoch` field, since the two overlap and thus establishing our write-what-where primitive.

It is also noted that there are no checks to the destination address calculated through: `dataPtr+dataLen` (e.g. whether it wraps around the address space), which allows us to write anywhere in memory.



**UAF 2: Establishing arbitrary read primitive**

class A: Note's 1 string (content)
class B: Note's 2 string's data
Now by editing Note 2 we can alter the string class of Note 1. So in order to achieve the arbitrary read, we edit Note 2 in prepend mode (i.e. insert at the beginning of the string) and add as data the address from which we want to read from. Since we are overwriting the dataPtr of Note's 1 string, by printing Note 1 we are effectively reading the data from the address we provided. To test whether we successfully managed to allocate class B to class A, we use as data of Note 2 the base address of the program which we leaked through UAF1. When successful, reading class A should output the PE signature.



**UAF 3: Redirecting control flow**

class A: Note 1 string's data (len <16)
class B: Note 2

Create a fake vtable and have its first entry point to the target address where we plan on redirecting the control flow. Then edit Note 1 with the address of the fake vtable (in prepend mode). Since it overlaps with Note 2, we are also modifying the `vptr` of Note 2, and thus by printing Note 2 we manage to redirect the control flow to the target address. 



**Putting everything together**

Now let's put everything together and get the flag. The plan is to take over the vtable of the controlled note and through that, manipulate the control flow of the program to allow the execution of arbitrary code. 

Redirecting control flow, as we have seen earlier is easy since we can manipulate the vptr of an object and the program doesn't utilise any form of control flow integrity. Essentially the program has an instruction similar with: `call qword ptr [rax]` and we have control over the `rax` register.  Since we don't have (easy) access to the stack, this essentially allows us to execute a single gadget. But in our case, executing a single gadget wouldn't get us to our goal of getting arbitrary code execution (e.g. we would need at least two gadgets, one to load `rcx` and another to call `system`). The following are couple of options we have to work around this issue:

1. Stack pivoting. Use a gadget to switch the stack to a user controlled area in memory, where we will be able able to utilise a rop chain bypassing the single gadget limit.

2. Something similar with jump oriented programming (kind of limited number of gadgets in our case, but shouldn't be impossible)

3. Create a register state through multiple invocations of the controlled virtual function (e.g. using registers that are not used between different calls and gadgets that return normally) and finish with with a gadget that can set `rcx` and call system. Easier said than done.

4. One-gadget (good luck on windows)

Stack pivoting appears to be our best option. Now let's hunt for some gadgets on x64. We first start by observing the register state upon execution of the `print` function, where we see a number of heap pointers. That's some good news, since the registers holding those pointers could be used for our stack pivoting, assuming we can leak their values. After further investigation on the heap pointers in our register state we get the following information:
   
   - `rcx` holds a pointer to the Note object since we are calling a non static function
   - `rdx` holds the  `vectorUserBegin`
   - `r8` holds the `vectorUserEnd`
   
Going through the limited number of available/usable stack pivoting gadgets, we get the following gadget which involves the `r8` register:

```{assembly}
KERNELBASE!SwitchToFiberContext+0x1f9:(ver 2004)
    mov rsp, qword ptr [r8 + 0x98]
    ret
```

 For reference, we know that `vectorUserEnd = vectorUserBegin + 8 * numberOfCreatedNotes`. The `numberOfCreatedNotes` is the number of notes we have created which is a value we already know. So now, if we can find the address of `vectorUserBegin`, we would be able calculate the `vectorUserEnd` which would allow us to use this gadget for our stack pivoting!

Now the question becomes, how can we leak the address of `vectorUserBegin`? 

A quick reminder before answering that question, the registers `rcx` and `rdx` hold the first two arguments for function calls in the windows x64 fast-call calling convention. So if we could make the first bytes of the controlled note contain the format specifier `%p` for example (i.e. address pointed by `rcx`), and use the UAF3 to change the note's vtable so as it calls printf instead of print, then we should be able to leak the address of `vectorUserBegin`.  So we could convert the original: `print(rcx)`=>`printf(rcx, rdx)` where `rcx` point to our format specifier.

Sounds perfect, but in practice we have a small problem. The first 8 bytes of a note contain the `vptr` of the object. So to make it work, it has to be a valid format specifier and point to a vtable that contains the printf (i.e. `vptr[0]=printf`) at the same time. 

After taking another look at our binary, we observe that the `.data` section, which is writable, has RVA 0x6000. Combined with the fact that the base address of the program is 64k aligned, we might be able to sneak a format specifier in the last two bytes of an address in the `.data` section.

Now we can use the UAF1 to write to an address in the `.data` section which is of the format: XXXX6A~1~A~2~A~3~

The X parts of the address should be "random" and out of our control.

Nevertheless, A~1~A~2~A~3~ are user controlled. We also note that bytes between 0x60 to 0x6f map mostly to English letters and we target x86, the byte-order of which is little-endian.

So we can set for example A~1~=9 and A~2~A~3~=25

`newVptr=0xXXXXXXXX6925`

we then write at the `newVptr` the address of `printf`

Then we replace the `vptr` of our note with `newVptr` using the UAF3. 

That causes the call of: `newVptr[0]("\x25\x69\x.....")` which in our case translates to `printf("%i.....", vectorUserBegin)`

So even though we can leak part of the `vectorUserBegin` through this approach (e.g. in the given example, 32 bits) we don't have a format modifier available (between 0x60-0x6f) to output the whole value of `vectorUserBegin`. To work around this limitation, we can run twice the printf function, first with `%g` (double) and then with `%i` (int) format modifiers. We can then use the upper 16 bits leaked through the format modifier `%g` (printf by default prints the six significant digits so we lose some accuracy in the lower parts of the original number), the lower 32bits of `%i`, and combine them to get the full 48bit address of `vectorUserBegin`

So now with the knowledge of `vectorUserBegin` we can calculate the value of the `vectorUserEnd` and thus we can use the identified stack pivot gadget. The plan now is to load the `r8 + 0x98` with the address of our new stack and set up our new stack with our rop chain using the arbitrary write from UAF1. Finally using the UAF3, change the vtable of the note to have it call our stack pivoting gadget and print it to initiate our rop chain. For the new stack, we create a note which we expand appropriately to have enough space to facilitate the call to `system` in this case (around 10k bytes) and the address of which we leak using the arbitrary read of UAF2 by walking through the `vectorUserBegin`.

The rop chain we use is simple:

```assembly
00: gadget2
08: commandAddr ;"type flag.txt"
10: systemAddr
18: main ;avoid crashing the app at the end
```

The gadget2 loads the `rcx` register as shown below:

```assembly
ntdll!atan2+0x61f: ;original inst: mulsd xmm0, xmm3
    pop rcx
    ret
```

After writing our fake vtable and writing our ROP chain, printing the "magic" note nicely prints the flag: CTF{eeeeeezzz_as_pi}



Comments:

1. Alternative ways of leaking `VectorUserBegin`:
   - Even though it is difficult to write into the stack through a string object (note validation checks), there is no code to prevent reading from the stack. Since the `VectorUserBegin` is stored into the stack during the `print` function call, then it should be possible to have its value leaked.
   - Estimate the final size of the vector, create and free a note with that size. Then use the default heap `ListHint` to leak its address. After that, allocate note(s) to make the vector expand to its final size. Assuming we work with the backend allocator, the vector should receive the address we already leaked.  
2. A potentially easier way of leaking object addresses is through the backend `ListHint`. We allocate an object of a target size, free that object, leak its address through the `ListHint` and then allocate the target object. We should receive the leaked address. It should also be useful to prevent the activation of the LFH by modifying the counters in the `FrontEndHeapUsageData`. Here we rely on the heap internals, which would require significant changes in the exploitation code in certain windows versions.
3. Hijack the list where vector elements are stored using the UAF. For example, you know that upon the creation of `x+1` notes the vector list is expanded to `k` bytes. Start by creating a `k` byte note. Then create a total of `x` notes. After that filter the `k`-byte note and create another note. Choose a `k` such that it doesn't fall within the LFH and the vector list will most likely allocated to our free'd note.
4. Even though there are some measures to avoid writing to the stack through the string object it should still be possible to achieve that by manipulating for example the default heap structure.
   - with backend: create a fake chunk on the stack (e.g. chunk header+flink+blink=24 bytes, so we could use the stack data controlled in the edit function). flink,blink point to heap->freelist (sentinel node), modify heap->freelist->flink,blink=userStackAddr, modify the BlocksIndex->ListHints[fakeSize>>3]=userStackAddr. On the next heap allocation of fakeSize (or a size smaller but not serviced by LFH), we should get our stack address back. (tested on 1903)
   - with LFH: activate LFH for a target blocksize and create a fake UserBlocks on the stack. Then change the UserBlocks of the active subsegment for the target blocksize. We should be able to allocate stack memory to our note chr* (tested on 1903 but with 0x38 controlled data on the stack)
5. One potential optimisation is to have the UAF3 substitute the UAF1. 
