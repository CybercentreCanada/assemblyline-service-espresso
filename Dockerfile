FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH espresso.espresso.Espresso

# Get required apt packages
RUN apt-get update && apt-get install -y \
   oracle-java8-installer

# Switch to assemblyline user
USER assemblyline

# Clone Espresso service code
WORKDIR /opt/al_service
COPY . .