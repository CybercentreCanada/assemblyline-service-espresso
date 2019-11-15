FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH espresso.Espresso

RUN apt-get update && apt-get install -y \
  openjdk-8-jre-headless \
  java-common

RUN mkdir -p /opt/al/support/espresso

RUN wget -O /opt/al/support/espresso/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.148/cfr-0.148.jar

# Switch to assemblyline user
USER assemblyline

# Copy Espresso service code
WORKDIR /opt/al_service
COPY . .
