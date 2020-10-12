# European Cyber Security Challenge (ECSC): National Cyprus Team Qualifications

Here are some challenges I've created for the selection of the Cyprus national team for the ECSC. 

## [pwn] echo
Security features: partial relro, pic, aslr
<br >
Goal: get the contents of argv[1]

## [pwn] echo2
Security features: partial relro, aslr

## [pwn] echo3
Security features: full relro, pic, aslr

## [reversing] broken_phone
The participants were only given the stripped binary.

## Remarks
The pwn challenges were served over tcp: 
<br >

	LD_LIBRARY_PATH=. socat -T 5 tcp-l:1234,reuseaddr,fork exec:bin
Finally, echo and echo3 have much simpler solutions (but still interesting) than those provided here.
