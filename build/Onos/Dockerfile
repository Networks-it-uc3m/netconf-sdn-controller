FROM onosproject/onos:2.7-latest


RUN apt-get update && \
    apt-get install -y wget ssh sshpass
# Copy the scripts into the container
COPY ./setup_controller.sh ./setup_controller.sh
COPY ./onos_critique.sh ./onos_critique.sh    
COPY ./ccips-app-1.0.0.oar ./ccips-app-1.0.0.oar
RUN ls -l /


ENTRYPOINT ["./setup_controller.sh"]
