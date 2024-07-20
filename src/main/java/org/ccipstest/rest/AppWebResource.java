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

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;


import static org.slf4j.LoggerFactory.getLogger;

import java.util.UUID;
import java.util.regex.Pattern;
/**
 * Sample web resource.
 */

@Path("ccips")
public class AppWebResource extends AbstractWebResource {
    private final Logger log = LoggerFactory.getLogger(getClass());

    @POST
    @Path("")
    @Consumes({"application/yaml", MediaType.APPLICATION_JSON})
    public Response createIpsecConfig(RequestDTO reqdto) throws Exception {
        try {
            reqdto.validate();
            request req = RequestDTO.transformToRequest(reqdto);
            String uri_device_1 = "netconf:" + req.getNodes()[0].getIpControl() + ":830";
            String uri_device_2 = "netconf:" + req.getNodes()[1].getIpControl() + ":830";
            DeviceId new_device_1 = DeviceId.deviceId(uri_device_1);
            DeviceId new_device_2 = DeviceId.deviceId(uri_device_2);
            NetconfSession newDeviceSession_1 = StorageHandler.controller.getNetconfDevice(new_device_1).getSession();
            NetconfSession newDeviceSession_2 = StorageHandler.controller.getNetconfDevice(new_device_2).getSession();
            StorageHandler.createHandler(req, newDeviceSession_1, newDeviceSession_2);
            return Response.ok().build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error editing Netconf config: "+e.getMessage()+"\n").build();
        }
    }

    @GET
    @Path("/{id}")
    public Response getIpsecConfig(@PathParam("id") String id) throws Exception {
        try {
            Handler response = null;
            response = StorageHandler.storage.get(Long.parseLong(id));
            if(response==null){
                throw new Exception("Handler with reqId : " + id + " does not exist");
            }
            return Response.status(Response.Status.OK).entity(response.toString()).build();
        }catch (Exception e){
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error getting tunnel information: "+e.getMessage()+"\n").build();
        }
    }

    @DELETE
    @Path("/{id}")
    public Response deleteIpsecConfig(@PathParam("id") String id) throws Exception {
        try {
            StorageHandler.deleteHandler(null,id);
            return Response.ok().build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error deleting handler : "+e.getMessage()+"\n").build();
        }

    }

    @GET
    @Path("")
    public Response getAllIpsecConfigs() throws Exception {
        log.info(StorageHandler.storage.toString());
        return Response.status(Response.Status.OK).entity(StorageHandler.storage.toString()).build();
    }

    @POST
    @Path("get-config-node")
    @Consumes({"application/yaml", MediaType.APPLICATION_JSON})
    public Response getConfigNode(RequestGetConfigDTO req) throws Exception {
        String netconfMessage;
        String netconfMessageXml;
        try {
            req.validateIPs();
            String uri_device = "netconf:"+req.getIp()+":830";
            DeviceId new_device = DeviceId.deviceId(uri_device);
            NetconfSession newDeviceSession = StorageHandler.controller.getNetconfDevice(new_device).getSession();
            netconfMessage = newDeviceSession.getConfig(DatastoreId.datastore("running"));
            netconfMessageXml=XmlFormatter.formatXml(netconfMessage);
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error getting config: " + e.getMessage() + "\n").build();
        }
        return Response.ok(netconfMessageXml).build();
    }

    @POST
    @Path("stop")
    @Consumes({"application/yaml", MediaType.APPLICATION_JSON})
    public Response stop(RequestReqidSpiDTO request_stop) throws Exception {
        try {
            request_stop.validate();
            StorageHandler.stopTunnel(request_stop.getName(), request_stop.getReqId());
            return Response.ok().build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error stopping tunnel" + e.getMessage() + "\n").build();
        }
    }

    @POST
    @Path("/certificate")
    @Consumes({ "application/yaml", MediaType.APPLICATION_JSON })
    public Response createCertificate(String certificate) throws Exception {

        CertificateStore.storeCertificate(certificate);
        return Response.ok().build();
    }

    @GET
    @Path("/certificate/{id}")
    public Response getCertificate(@PathParam("id") String id) throws Exception {
        UUID certID;
        try {
            certID = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Invalid UUID").build();
        }

        String certificate = CertificateStore.getCertificate(certID);

        if (certificate == null) {
            return Response.status(Response.Status.NOT_FOUND).entity("Certificate not found").build();
        }

        return Response.ok(certificate, MediaType.APPLICATION_JSON).build();
    }

    @GET
    @Path("/certificate")
    public Response getAllCertificates() throws Exception {
        return Response.status(Response.Status.OK).entity(CertificateStore.certs.toString()).build();
    }

    

    public static class RequestReqidSpiDTO {
        String reqId;
        String name;

        public String getReqId() {
            return this.reqId;
        }

        public void setReqId(String reqId) {
            this.reqId = reqId;
        }

        public String getName() {
            return this.name;
        }

        public void setName(String name) {
            this.name = name;
        }

        private void validate() throws Exception {
            if (!isNonNegativeNumber(reqId)) throw new Exception("Invalid reqId");
        }

        private boolean isNonNegativeNumber(String value) {
            try {
                return Long.parseLong(value) > 0; //0 is not valid
            } catch (NumberFormatException e) {
                return false;
            }
        }
    }

    public static class RequestGetConfigDTO {
        private static final Pattern IP_PATTERN = Pattern.compile(
                "^(([0-9]{1,3}\\.){3}[0-9]{1,3})$");
        String ip;

        public String getIp() {
            return ip;
        }

        public void setIp(String ip) {
            this.ip = ip;
        }

        private void validateIPs() throws Exception {
            if (!isIPValid(ip)) throw new Exception("Invalid ip format");
        }

        private boolean isIPValid(String ip) {
            return ip != null && IP_PATTERN.matcher(ip).matches();
        }


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
        private static final Pattern IP_PATTERN = Pattern.compile(
                "^(([0-9]{1,3}\\.){3}[0-9]{1,3})$");

        public void validate() throws Exception {
            validateIPs();
            validateAlgs();
            validateSoftAndHardValues();
        }

        private void validateIPs() throws Exception {
            if (!isIPValid(ipData1)) throw new Exception("Invalid ipData1");
            if (!isIPValid(ipControl1)) throw new Exception("Invalid ipControl1");
            if (!isIPValid(ipData2)) throw new Exception("Invalid ipData2");
            if (!isIPValid(ipControl2)) throw new Exception("Invalid ipControl2");
        }

        private boolean isIPValid(String ip) {
            return ip != null && IP_PATTERN.matcher(ip).matches();
        }

        private void validateAlgs() throws Exception {
            if (!Algs.ENCALGS.containsKey(encAlg)) throw new Exception("Invalid encAlg");
            if (!Algs.AUTHALGS.containsKey(intalg)) throw new Exception("Invalid intalg");
        }

        private void validateSoftAndHardValues() throws Exception {
            if (!isNonNegativeNumber(nBytesSoft)) throw new Exception("Invalid nBytesSoft");
            if (!isNonNegativeNumber(nPacketsSoft)) throw new Exception("Invalid nPacketsSoft");
            if (!isNonNegativeNumber(nTimeSoft)) throw new Exception("Invalid nTimeSoft");
            if (!isNonNegativeNumber(nTimeIdleSoft)) throw new Exception("Invalid nTimeIdleSoft");
            if (!isNonNegativeNumber(nBytesHard)) throw new Exception("Invalid nBytesHard");
            if (!isNonNegativeNumber(nPacketsHard)) throw new Exception("Invalid nPacketsHard");
            if (!isNonNegativeNumber(nTimeHard)) throw new Exception("Invalid nTimeHard");
            if (!isNonNegativeNumber(nTimeIdleHard)) throw new Exception("Invalid nTimeIdleHard");
        }

        private boolean isNonNegativeNumber(String value) {
            try {
                return Long.parseLong(value) >= 0;
            } catch (NumberFormatException e) {
                return false;
            }
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


}
