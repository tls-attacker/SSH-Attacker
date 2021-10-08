# A simple Dockerfile to create a maven image containing the SSH-Attacker modules
# Can be removed safely once the SSH-Attacker can be installed by maven directly
FROM maven:3.8.3-jdk-11
WORKDIR /usr/src/ssh-attacker

# Adding the dependencies first allows docker to skip dependency installation using the build cache
COPY pom.xml license_header_plain.txt ./
COPY SSH-Project-Template/pom.xml ./SSH-Project-Template/pom.xml
COPY SSH-Client/pom.xml ./SSH-Client/pom.xml
COPY SSH-Core/pom.xml ./SSH-Core/pom.xml
# We can't install the dependencies for the SSH-Client (yet), because it depends on SSH-Core
RUN mvn --projects SSH-Core dependency:resolve dependency:resolve-plugins

# Add modules of the SSH-Attacker
COPY SSH-Project-Template ./SSH-Project-Template/
COPY SSH-Client ./SSH-Client/
COPY SSH-Core ./SSH-Core/
# Build 'em
RUN mvn clean install