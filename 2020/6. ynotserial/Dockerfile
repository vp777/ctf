 FROM openjdk:15-jdk-slim
 
 WORKDIR /ctf

 COPY docker_files/init.sh ./
 COPY docker_files/server.jar ./
 COPY docker_files/flag.txt ./
 
 RUN chmod +x ./init.sh
 
 CMD ["./init.sh"]
