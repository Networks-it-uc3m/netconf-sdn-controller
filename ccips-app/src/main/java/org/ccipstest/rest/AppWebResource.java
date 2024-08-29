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
import org.onosproject.netconf.NetconfSession;
import org.onosproject.rest.AbstractWebResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.UUID;
import java.util.regex.Pattern;
/**
 * Web resource.
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
        } catch (Exception e) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error creating Ipsec config: " + e.getMessage() + "\n").build();
        }
        Handler h;
        try {
            request req = RequestDTO.transformToRequest(reqdto);
            String uri_device_1 = "netconf:" + req.getNodes()[0].getIpControl() + ":830";
            String uri_device_2 = "netconf:" + req.getNodes()[1].getIpControl() + ":830";
            DeviceId new_device_1 = DeviceId.deviceId(uri_device_1);
            DeviceId new_device_2 = DeviceId.deviceId(uri_device_2);
            NetconfSession newDeviceSession_1 = StorageHandler.controller.getNetconfDevice(new_device_1).getSession();
            NetconfSession newDeviceSession_2 = StorageHandler.controller.getNetconfDevice(new_device_2).getSession();
            h = StorageHandler.createHandler(req, newDeviceSession_1, newDeviceSession_2);
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error creating Ipsec config: "+e.getMessage()+"\n").build();
        }
        return Response.ok(h,MediaType.APPLICATION_JSON).build();
    }

    @GET
    @Path("/{id}")
    public Response getIpsecConfig(@PathParam("id") String id) throws Exception {
        if(isIdValid(id)){
            return Response.status(Response.Status.BAD_REQUEST).entity("Error getting tunnel information: Id is not valid\n").build();
        }
        Handler response = null;
        try {
            response = StorageHandler.storage.get(Long.parseLong(id));
            if(response==null){
                return Response.status(Response.Status.NOT_FOUND).entity("Error getting tunnel information: Tunnel with reqId " + id + " does not exist").build();
            }
        }catch (Exception e){
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error getting tunnel information: "+e.getMessage()+"\n").build();
        }
        return Response.status(Response.Status.OK).entity(response.toString()).build();
    }

    @DELETE
    @Path("/{id}")
    public Response deleteIpsecConfig(@PathParam("id") String id) throws Exception {
        if (isIdValid(id)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Error deleting tunnel: Id is not valid\n").build();
        }
        try {
            StorageHandler.deleteHandler(id);
        } catch (Exception e) {
            if (e.getMessage().contains("Handler with id") && e.getMessage().contains("does not exist")) {
                return Response.status(Response.Status.NOT_FOUND).entity("Error deleting tunnel: " + e.getMessage() + "\n").build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error deleting tunnel: " + e.getMessage() + "\n").build();
        }
        return Response.status(Response.Status.OK).entity("Tunnel with reqId " + id + " was succesfully removed.").build();

    }

    @GET
    @Path("")
    public Response getAllIpsecConfigs() throws Exception {
        log.info(StorageHandler.storage.toString());
        return Response.status(Response.Status.OK).entity(StorageHandler.storage.toString()).build();
    }

    @POST
    @Path("/certificate")
    @Consumes({ "application/yaml", MediaType.APPLICATION_JSON })
    public Response createCertificate(String certificate) throws Exception {
        try {
            CertificateStore.storeCertificate(certificate);
            return Response.ok().build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Error storing certificate: " + e.getMessage() + "\n").build();
        }
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

    public static boolean isIdValid(String id) {
        if (id == null || id.isEmpty()) {
            return true;
        }

        try {
            long number = Long.parseLong(id);

            return number <= 0;
        } catch (NumberFormatException e) {
            return true;
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
            if (isIpValid(ipData1)) throw new Exception("Invalid ipData1");
            if (isIpValid(ipControl1)) throw new Exception("Invalid ipControl1");
            if (isIpValid(ipData2)) throw new Exception("Invalid ipData2");
            if (isIpValid(ipControl2)) throw new Exception("Invalid ipControl2");
        }

        private boolean isIpValid(String ip) {
            return ip == null || !IP_PATTERN.matcher(ip).matches();
        }

        private void validateAlgs() throws Exception {
            if (!Algs.ENCALGS.containsKey(encAlg)) throw new Exception("Invalid encAlg");
            if (!Algs.AUTHALGS.containsKey(intalg)) throw new Exception("Invalid intalg");
        }

        private void validateSoftAndHardValues() throws Exception {
            if (isNumberNonNegative(nBytesSoft)) throw new Exception("Invalid nBytesSoft");
            if (isNumberNonNegative(nPacketsSoft)) throw new Exception("Invalid nPacketsSoft");
            if (isNumberNonNegative(nTimeSoft)) throw new Exception("Invalid nTimeSoft");
            if (isNumberNonNegative(nTimeIdleSoft)) throw new Exception("Invalid nTimeIdleSoft");
            if (isNumberNonNegative(nBytesHard)) throw new Exception("Invalid nBytesHard");
            if (isNumberNonNegative(nPacketsHard)) throw new Exception("Invalid nPacketsHard");
            if (isNumberNonNegative(nTimeHard)) throw new Exception("Invalid nTimeHard");
            if (isNumberNonNegative(nTimeIdleHard)) throw new Exception("Invalid nTimeIdleHard");
        }

        private boolean isNumberNonNegative(String value) {
            try {
                return Long.parseLong(value) < 0;
            } catch (NumberFormatException e) {
                return true;
            }
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
