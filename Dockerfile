ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH espresso.Espresso

USER root

# The following line fix an issue with openjdk installation
RUN mkdir -p /usr/share/man/man1

RUN apt-get update && apt-get install -y wget default-jre-headless java-common && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/al/support/espresso

RUN wget -O /opt/al/support/espresso/cfr.jar https://github.com/leibnitz27/cfr/releases/download/0.151/cfr-0.151.jar

# Switch to assemblyline user
USER assemblyline

# Copy Espresso service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
