FROM openjdk:8 as build
LABEL maintainer="Midhlaj <midhlaj.vs@nexquare.io>"
RUN mkdir -p /usr/local/src/cas-overlay \
  && cd /usr/local/src \
  && mkdir -p /usr/share/man/man1 \
  && apt-get update \
  && apt-get install -y --no-install-recommends git gradle  
COPY ./ /usr/local/src/cas-overlay
WORKDIR /usr/local/src/cas-overlay

RUN ./build.sh package

FROM openjdk:8-alpine

RUN mkdir /etc/cas \
  && mkdir -p /usr/local/src \
  && cd /etc/cas \
  && keytool -genkey -noprompt -keystore thekeystore -storepass changeit -keypass changeit -validity 3650 \
             -keysize 2048 -keyalg RSA -dname "CN=localhost, OU=Devops, O=Nex, L=Bangalore, S=KA, C=IN"

COPY --from=build /usr/local/src/cas-overlay/target/ /usr/local/src/cas-overlay

ENV PATH="/usr/local/src/cas-overlay:${PATH}"
WORKDIR /usr/local/src/cas-overlay

COPY etc/cas /etc/cas
EXPOSE 8443 8080

CMD [ "java", "-jar", "cas.war" ]
