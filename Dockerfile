# A simple Dockerfile to create a maven images containing the SSH-Attacker modules.
#
# To build this Dockerfile one needs to pass a maven settings.xml with access to the internal Nexus repository along the build command.
# This requires one to use BuildKit (export DOCKER_BUILDKIT=1 or enabled by default on newer Docker releases).
# Example:
#     docker build . --target ssh-client -t ssh-client:latest --secret id=m2settings,src=/path/to/.m2/settings.xml
FROM maven:3.8.6-jdk-11 AS builder
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake git libssl-dev && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch 0.7.2 https://github.com/open-quantum-safe/liboqs.git && cmake -S liboqs -B liboqs/build -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON && cmake --build liboqs/build --parallel "$(nproc)" && cmake --build liboqs/build --target install
RUN git clone --depth 1 --branch master https://github.com/open-quantum-safe/liboqs-java.git && cd liboqs-java && mvn install -P linux -Dliboqs.include.dir="/usr/local/include" -Dliboqs.lib.dir="/usr/local/lib" -DskipTests=true && cd ..
WORKDIR /usr/src/sshattacker

# Adding the dependencies first allows docker to skip dependency installation using the build cache
COPY pom.xml license_header_plain.txt ./
COPY Attacks/pom.xml ./Attacks/pom.xml
COPY SSH-Client/pom.xml ./SSH-Client/pom.xml
COPY SSH-Core/pom.xml ./SSH-Core/pom.xml
COPY SSH-Core-OQS/pom.xml ./SSH-Core-OQS/pom.xml
COPY SSH-Mitm/pom.xml ./SSH-Mitm/pom.xml
COPY SSH-Server/pom.xml ./SSH-Server/pom.xml
# We can only install dependencies for SSH-Core here since the other modules depend on SSH-Core to be built
RUN --mount=type=secret,id=m2settings,dst=/root/.m2/settings.xml \
    mvn --projects SSH-Core dependency:resolve dependency:resolve-plugins

# Add modules of the SSH-Attacker
COPY Attacks ./Attacks
COPY SSH-Client ./SSH-Client/
COPY SSH-Core ./SSH-Core/
COPY SSH-Core-OQS ./SSH-Core-OQS/
COPY SSH-Mitm ./SSH-Mitm/
COPY SSH-Server ./SSH-Server/

# Build 'em
RUN --mount=type=secret,id=m2settings,dst=/root/.m2/settings.xml \
    mvn install -DskipTests=true -Dmaven.javadoc.skip=true

# Introduce a separate build stage for runtime to reduce resulting image sizes
FROM openjdk:11-slim AS runtime
# Install OpenSSL, because liboqs requires OpenSSL's libcrypto as a runtime
# depedency.
RUN apt-get update && apt-get install -y --no-install-recommends libssl1.1 && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/app
ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib
COPY --from=builder /usr/local/ /usr/local
COPY --from=builder /usr/src/sshattacker/apps /usr/src/app/

# Separate stages for each executable submodule
FROM runtime AS attacks
ENTRYPOINT ["java", "-jar", "Attacks.jar"]

FROM runtime AS ssh-client
ENTRYPOINT ["java", "-jar", "SSH-Client.jar"]

FROM runtime AS ssh-mitm
ENTRYPOINT ["java", "-jar", "SSH-Mitm.jar"]

FROM runtime AS ssh-server
ENTRYPOINT ["java", "-jar", "SSH-Server.jar", "-port", "22"]
EXPOSE 22
