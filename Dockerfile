ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH espresso.Espresso
ENV CFR_VERSION=0.152

USER root

# The following line fix an issue with openjdk installation
RUN mkdir -p /usr/share/man/man1

RUN apt-get update && apt-get install -y wget default-jre-headless java-common && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/al/support/espresso

RUN wget -O /opt/al/support/espresso/cfr.jar https://github.com/leibnitz27/cfr/releases/download/$CFR_VERSION/cfr-$CFR_VERSION.jar

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy Espresso service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
