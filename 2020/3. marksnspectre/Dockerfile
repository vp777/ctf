 FROM amd64/ubuntu:18.04
 
 RUN apt-get update && apt-get install -y gcc
 
 WORKDIR /marksnspectre
 COPY docker_files/parent ./
 COPY docker_files/libmns.so ./
 COPY docker_files/start.sh ./
 COPY docker_files/init.sh ./
 COPY docker_files/main.c ./
 COPY docker_files/socat ./
 RUN chmod +x ./init.sh
 RUN chmod +x ./start.sh
 RUN chmod +x ./socat

 CMD ["./init.sh"]

