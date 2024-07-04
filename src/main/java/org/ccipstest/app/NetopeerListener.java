package org.ccipstest.app;

import org.onosproject.net.DeviceId;
import org.onosproject.netconf.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class NetopeerListener implements NetconfDeviceListener {
    private final Logger log = LoggerFactory.getLogger(getClass());
    private NetconfController controller = null;
    public NetopeerListener(NetconfController controller) {
        this.controller=controller;

    }

    @Override
    public void deviceAdded(DeviceId di){

        log.info("\nDEVICE ADDED: " + di + "\n");
        NetconfSession session = this.controller.getNetconfDevice(di).getSession();
        try {
            this.controller.getNetconfDevice(di).getSession().startSubscription();
        } catch (NetconfException e) {
            throw new RuntimeException(e);
        }
        NetconfDeviceOutputEventListenerLifetime OutputListener = new NetconfDeviceOutputEventListenerLifetime();
        try {
            session.addDeviceOutputListener(OutputListener);
        } catch (NetconfException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public void deviceRemoved(DeviceId deviceId) {

    }


}