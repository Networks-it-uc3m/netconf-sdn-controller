/*
 * Copyright 2024-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.ccipstest.rest;


import org.ccipstest.app.*;
import org.onosproject.net.DeviceId;
import org.onosproject.netconf.DatastoreId;
import org.onosproject.netconf.NetconfController;
import org.onosproject.netconf.NetconfSession;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


import static org.slf4j.LoggerFactory.getLogger;
/**
 * Sample web resource.
 */

@Path("sample")
public class AppWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(getClass());
    /**
     * Get hello world greeting.
     *
     * @return 200 OK
     */
    @GET
    @Path("")
    public Response getGreeting() {

        ObjectNode node = mapper().createObjectNode().put("hello", "world");
        return ok(node).build();
    }

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetconfController netconfController;

    // Inject the NetconfService



    @POST
    @Path("storage")
    public Response Storage() throws Exception {
        log.info("ESTO ES LO QUE HAY DENTRO DEL HASH MAP DE HANDLERS:\n"+StorageHandler.storage);
        StorageHandler.stopTunnel(new RequestDeleteDTO(null,"out/172.20.0.3/in/172.20.0.2"));
        log.info("ESTO ES LO QUE HAY DENTRO DEL HASH MAP DE HANDLERS:\n"+StorageHandler.storage);
        return Response.ok().build();

    }

    @POST
    @Path("reek1")
    public Response Reek1() throws Exception {
        StorageHandler.rekey("out/172.20.0.2/in/172.20.0.3_1");
        StorageHandler.rekey("out/172.20.0.3/in/172.20.0.2_2");
        return Response.ok().build();

    }

    @POST
    @Path("delete")
    @Consumes({"application/yaml", MediaType.APPLICATION_JSON})
    public Response delete(RequestDeleteDTO request_del) throws Exception {
        try {
            StorageHandler.stopTunnel(request_del);
            return Response.ok().build();
        } catch (Exception e) {
            log.info("Exception while stopping tunnel: ", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error stopping tunnel: " + e.getMessage())
                    .build();
        }
    }

    @POST
    @Path("edit-netconf")
    @Consumes({"application/yaml", MediaType.APPLICATION_JSON})
    public Response editNetconfConfig(RequestDTO reqdto) throws Exception {
        request req = RequestDTO.transformToRequest(reqdto);
        String uri_device_1 = "netconf:"+req.getNodes()[0].getIpControl()+":830";//Cambiar por variable del request
        String uri_device_2 = "netconf:"+req.getNodes()[1].getIpControl()+":830";
        DeviceId new_device_1= DeviceId.deviceId(uri_device_1);
        DeviceId new_device_2= DeviceId.deviceId(uri_device_2);
        NetconfSession newDeviceSession_1 = StorageHandler.controller.getNetconfDevice(new_device_1).getSession();
        NetconfSession newDeviceSession_2 = StorageHandler.controller.getNetconfDevice(new_device_2).getSession();
        StorageHandler.createHandler(req,newDeviceSession_1,newDeviceSession_2);
        return Response.ok().build();


    }

    public static class RequestDTO {
        public String networkInternal1;
        public String ipData1;
        public String ipControl1;
        public String networkInternal2;
        public String ipData2;
        public String ipControl2;
        public String encAlg;
        public String intalg;
        public String nBytesSoft;
        public String nPacketsSoft;
        public String nTimeSoft;
        public String nTimeIdleSoft;
        public String nBytesHard;
        public String nPacketsHard;
        public String nTimeHard;
        public String nTimeIdleHard;

        public static request transformToRequest(RequestDTO dto) {
            Node[] nodes = new Node[2];
            nodes[0] = new Node(dto.networkInternal1, null, dto.ipData1, dto.ipControl1);
            nodes[1] = new Node(dto.networkInternal2, null, dto.ipData2, dto.ipControl2);

            LifetimeConfig softLifetime = new LifetimeConfig(dto.nBytesSoft, dto.nPacketsSoft, dto.nTimeSoft, dto.nTimeIdleSoft);
            LifetimeConfig hardLifetime = new LifetimeConfig(dto.nBytesHard, dto.nPacketsHard, dto.nTimeHard, dto.nTimeIdleHard);

            return new request(nodes, dto.encAlg, dto.intalg, softLifetime, hardLifetime);
        }

        public String getNetworkInternal1() {
            return networkInternal1;
        }

        public void setNetworkInternal1(String networkInternal1) {
            this.networkInternal1 = networkInternal1;
        }

        public String getIpData1() {
            return ipData1;
        }

        public void setIpData1(String ipData1) {
            this.ipData1 = ipData1;
        }

        public String getIpControl1() {
            return ipControl1;
        }

        public void setIpControl1(String ipControl1) {
            this.ipControl1 = ipControl1;
        }

        public String getNetworkInternal2() {
            return networkInternal2;
        }

        public void setNetworkInternal2(String networkInternal2) {
            this.networkInternal2 = networkInternal2;
        }

        public String getIpData2() {
            return ipData2;
        }

        public void setIpData2(String ipData2) {
            this.ipData2 = ipData2;
        }

        public String getIpControl2() {
            return ipControl2;
        }

        public void setIpControl2(String ipControl2) {
            this.ipControl2 = ipControl2;
        }

        public String getEncAlg() {
            return encAlg;
        }

        public void setEncAlg(String encAlg) {
            this.encAlg = encAlg;
        }

        public String getIntalg() {
            return intalg;
        }

        public void setIntalg(String intalg) {
            this.intalg = intalg;
        }

        public String getnBytesSoft() {
            return nBytesSoft;
        }

        public void setnBytesSoft(String nBytesSoft) {
            this.nBytesSoft = nBytesSoft;
        }

        public String getnPacketsSoft() {
            return nPacketsSoft;
        }

        public void setnPacketsSoft(String nPacketsSoft) {
            this.nPacketsSoft = nPacketsSoft;
        }

        public String getnTimeIdleSoft() {
            return nTimeIdleSoft;
        }

        public void setnTimeIdleSoft(String nTimeIdleSoft) {
            this.nTimeIdleSoft = nTimeIdleSoft;
        }

        public String getnTimeSoft() {
            return nTimeSoft;
        }

        public void setnTimeSoft(String nTimeSoft) {
            this.nTimeSoft = nTimeSoft;
        }

        public String getnBytesHard() {
            return nBytesHard;
        }

        public void setnBytesHard(String nBytesHard) {
            this.nBytesHard = nBytesHard;
        }

        public String getnPacketsHard() {
            return nPacketsHard;
        }

        public void setnPacketsHard(String nPacketsHard) {
            this.nPacketsHard = nPacketsHard;
        }

        public String getnTimeHard() {
            return nTimeHard;
        }

        public void setnTimeHard(String nTimeHard) {
            this.nTimeHard = nTimeHard;
        }

        public String getnTimeIdleHard() {
            return nTimeIdleHard;
        }

        public void setnTimeIdleHard(String nTimeIdle) {
            this.nTimeIdleHard = nTimeIdle;
        }

        @Override
        public String toString() {
            return "RequestDTO{" +
                    "networkInternal1='" + networkInternal1 + '\'' +
                    ", ipData1='" + ipData1 + '\'' +
                    ", ipControl1='" + ipControl1 + '\'' +
                    ", networkInternal2='" + networkInternal2 + '\'' +
                    ", ipData2='" + ipData2 + '\'' +
                    ", ipControl2='" + ipControl2 + '\'' +
                    ", encAlg='" + encAlg + '\'' +
                    ", intalg='" + intalg + '\'' +
                    ", nBytesSoft='" + nBytesSoft + '\'' +
                    ", nPacketsSoft='" + nPacketsSoft + '\'' +
                    ", nTimeSoft='" + nTimeSoft + '\'' +
                    ", nTimeIdleSoft='" + nTimeIdleSoft + '\'' +
                    ", nBytesHard='" + nBytesHard + '\'' +
                    ", nPacketsHard='" + nPacketsHard + '\'' +
                    ", nTimeHard='" + nTimeHard + '\'' +
                    ", nTimeIdle='" + nTimeIdleHard + '\'' +
                    '}';
        }
    }

    public static class SampleDTO {
        public String hello;

        public String getHello() {
            return hello;
        }

        public void setHello(String hello) {
            this.hello = hello;
        }

        @Override
        public String toString() {
            return "SampleDTO{" +
                    "hello='" + hello + '\'' +
                    '}';
        }
    }
}
