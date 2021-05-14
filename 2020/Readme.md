## 1. ezWin [pwn/windows]

Running the challenge:

`./docker_build.bat && ./docker_run.bat`

The application should be running on port 4444

By default, the container will run on hyper-v and is based on Windows Server Core 1909. Nevertheless it was tested in 1607 and 2004 so it's expected to run with every other version in between.



## 2. exploitguard [pwn/linux]: 

A vulnerable binary that is protected by a pintool implementing some anti-exploitation techniques, like shadow stack and heap corruption checks.


Running the challenge:

`./docker_build.sh && ./docker_run.sh`

Connect to port 7777 to interact with the application.

Goal is to exploit the hardened application and execute the "win" function


## 3. marksNspectre [spectre]:

Running the challenge:

`./docker_build.sh && ./docker_run.sh`

Then connect to port 1337 and give the contents of a c file  which will be compiled and linked against the libmns library. The function named "user_main()" from the user provided c code will then get executed.
Goal is to extract the contents of gdata.flag

Note, you are not meant to attack the sandbox but it should still be interesting if possible to find a way around it.

Referenes:

https://spectreattack.com/spectre.pdf



## 4. hellXSS [web]: 

This might turn your love for XSS into hate!

Running the challenge:

`./docker_build.sh && ./docker_run.sh 127.0.0.1`

The challenge will be running at: `http://127.0.0.1:5000` and there are two flags.



##  5. graydes [whitebox crypto]: 

Meant to be a playground for Side-Channel Analysis, so if you find this version easy, you can try solving it with SCA. It is noted that the pre-obfuscated code is susceptible to this class of attacks.



## 6. ynotserial [java deserialization]: 

Running the challenge:

`./docker_build.sh && ./docker_run.sh`

The service should be running on port 9999, goal is to get a shell on the server.



## 7. wtf [reversing]: 

small reversing challenge powered by ptrace.

Note: the flag is composed by printable characters (`0x20<=c<0x80`)



## Note

Unless a standalone binary is given, the players are supposed to be provided with the files inside the `challenge_files` directory.