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
package org.ccipstest.cli;
import org.ccipstest.app.*;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;

import org.ccipstest.app.StorageHandler;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.netconf.*;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

/**
 * Sample Apache Karaf CLI command.
 */



@Service
@Command(scope = "onos", name = "sample", description = "Sample Apache Karaf CLI command")
public class AppCommand extends AbstractShellCommand {



    /**@Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetconfController controller;*/

    @Override
    protected void doExecute() throws Exception {



//        String NAME = "out/192.168.201.254/192.168.202.254";
//        String REQ_ID = "12";
//        String SPI = "34502" ;
//        String EXT_SEQ_NUM = "true" ;
//        String SEQ_OVERFLOW = "false" ;
//        String LOCAL_PREFIX_IN = "10.0.2.15" ;
//        String LOCAL_PREFIX_OUT = "10.0.2.10";
//        String REMOTE_PREFIX_IN = "10.0.2.10" ;
//        String REMOTE_PREFIX_OUT = "10.0.2.15" ;
//
//
//        String INNER_PROTOCOL = "any" ;
//        String PROTOCOL_PARAMETERS = "esp" ;
//        LifetimeConfig hardLifetime = new LifetimeConfig("2000000","2000","50","240");
//        LifetimeConfig softLifetime = new LifetimeConfig("2000000","2000","10","240");;
//        String LOCAL_IN = "10.0.2.15" ;
//        String LOCAL_OUT = "10.0.2.10" ;
//        String REMOTE_IN = "10.0.2.10" ;
//        String REMOTE_OUT = "10.0.2.15" ;
//
//        /**VARIABLES PARA LA SPD (UTILIZA TMB ALGUNAS DE ARRIBA)*/
//        String DIRECTION = "inbound";
//        String ANTI_REPLAY_WINDOW_SIZE = "32" ;
//        String ACTION = "protect" ;
//        String INTEGRITY_ALGORITHM = "2";
//        String ENCRYPTION_ID="1";
//        String ENCRYPTION_ALGORITHM = "3";
//        String KEYLENGTH = "128";
//        DatastoreId netconfTargetConfig= DatastoreId.datastore("running");
//
//        String uri_device_1 = "netconf:10.0.2.15:830";
//        String uri_device_2 = "netconf:10.0.2.10:830";
//        DeviceId new_device_1= DeviceId.deviceId(uri_device_1);
//        DeviceId new_device_2= DeviceId.deviceId(uri_device_2);
//        NetconfSession newDeviceSession_1 = get(NetconfController.class).getNetconfDevice(new_device_1).getSession();
//        NetconfSession newDeviceSession_2 = get(NetconfController.class).getNetconfDevice(new_device_2).getSession();
//
//
//        /**newDeviceSession_1.addDeviceOutputListener(listener);*/
//
//        StorageHandler storagehandler = new StorageHandler();
//
//        String mode = "merge";
//        String newConfiguration_SAD_IN= Config.toString_add_sad("in/ 10.0.2.15/ 10.0.2.10",REQ_ID,SPI,EXT_SEQ_NUM,SEQ_OVERFLOW,"10.0.2.15/32","10.0.2.10/32",INNER_PROTOCOL,PROTOCOL_PARAMETERS,hardLifetime,softLifetime,LOCAL_IN,REMOTE_IN);
//        String newConfiguration_SAD_OUT=Config.toString_add_sad("out/ 10.0.2.15/ 10.0.2.10",REQ_ID,SPI,EXT_SEQ_NUM,SEQ_OVERFLOW,"10.0.2.10/32","10.0.2.15/32",INNER_PROTOCOL,PROTOCOL_PARAMETERS,hardLifetime,softLifetime,LOCAL_OUT,REMOTE_OUT);
//        String newConfiguration_SPD_IN=Config.to_String_add_spd("in/ 10.0.2.15/ 10.0.2.10",DIRECTION,REQ_ID,ANTI_REPLAY_WINDOW_SIZE,LOCAL_PREFIX_IN,REMOTE_PREFIX_IN,INNER_PROTOCOL,ACTION,EXT_SEQ_NUM,SEQ_OVERFLOW,PROTOCOL_PARAMETERS,INTEGRITY_ALGORITHM,ENCRYPTION_ID,ENCRYPTION_ALGORITHM,KEYLENGTH);
//        String newConfiguration_SPD_OUT=Config.to_String_add_spd("out/ 10.0.2.15/ 10.0.2.10","outbound",REQ_ID,ANTI_REPLAY_WINDOW_SIZE,LOCAL_PREFIX_OUT,REMOTE_PREFIX_OUT,INNER_PROTOCOL,ACTION,EXT_SEQ_NUM,SEQ_OVERFLOW,PROTOCOL_PARAMETERS,INTEGRITY_ALGORITHM,ENCRYPTION_ID,ENCRYPTION_ALGORITHM,KEYLENGTH);
//
//        String newConfiguration3=Config.toSpdDeleteXml("out/ 10.0.2.15/ 10.0.2.10",REQ_ID);
//        String newConfiguration4=Config.toSadDeleteXml("out/ 10.0.2.15/ 10.0.2.10",REQ_ID);
//
//        storagehandler.createHandler(
//                "Handler1",
//                newDeviceSession_1,
//                newDeviceSession_2,
//                mode,netconfTargetConfig,
//                newConfiguration_SAD_IN,
//                newConfiguration_SAD_OUT,
//                newConfiguration_SPD_IN,
//                newConfiguration_SPD_OUT,
//                newConfiguration3,
//                newConfiguration4
//        );


        /**
        String mode2 = "merge";
        String newConfiguration12=Config.toString_add_sad("out/ 192.168.201.255/ 192.168.202.255","13","40000",EXT_SEQ_NUM,SEQ_OVERFLOW,LOCAL_PREFIX,REMOTE_PREFIX,INNER_PROTOCOL,PROTOCOL_PARAMETERS,hardLifetime,softLifetime,LOCAL,REMOTE);
        String newConfiguration22=Config.to_String_add_spd("out/ 192.168.201.255/ 192.168.202.255",DIRECTION,"13",ANTI_REPLAY_WINDOW_SIZE,LOCAL_PREFIX1,REMOTE_PREFIX1,INNER_PROTOCOL,ACTION,EXT_SEQ_NUM,SEQ_OVERFLOW,PROTOCOL_PARAMETERS,INTEGRITY_ALGORITHM,ENCRYPTION_ID,ENCRYPTION_ALGORITHM,KEYLENGTH);
        String newConfiguration32=Config.toSpdDeleteXml("out/ 192.168.201.255/ 192.168.202.255","13");
        String newConfiguration42=Config.toSadDeleteXml("out/ 192.168.201.255/ 192.168.202.255","13");
        storagehandler.createHandler("Handler2",newDeviceSession_1,newDeviceSession_2,mode2,netconfTargetConfig,newConfiguration12,newConfiguration22,newConfiguration32,newConfiguration42);
        */
    }

}
