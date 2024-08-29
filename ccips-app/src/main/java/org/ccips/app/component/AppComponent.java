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
package org.ccips.app.component;

import org.ccips.app.handler.StorageHandler;
import org.ccips.app.listener.NetopeerListener;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.netconf.*;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class AppComponent  {

    private final Logger log = LoggerFactory.getLogger(getClass());

    private ApplicationId appId;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected NetconfController deviceController;

    @Activate
    protected void activate() throws NetconfException {
        appId = coreService.registerApplication("org.ccips.ccips-app");
        NetopeerListener netListener = new NetopeerListener(deviceController);
        deviceController.addDeviceListener(netListener);
        StorageHandler.controller = deviceController;

        log.info("\nCCIPS STARTED\n");

    }

    @Deactivate
    protected void deactivate() {
        log.info("\nCCIPS Stopped\n");
    }


}
