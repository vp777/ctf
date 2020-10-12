FROM mcr.microsoft.com/windows/servercore:1909

WORKDIR /ctf

ADD https://aka.ms/vs/16/release/vc_redist.x64.exe ./redist.exe
RUN .\redist.exe /quiet /install

ADD docker_files/ezWin.exe ./
ADD docker_files/AppJailLauncher.exe ./
ADD docker_files/run.cmd ./
ADD docker_files/flag.txt ./

CMD .\run.cmd