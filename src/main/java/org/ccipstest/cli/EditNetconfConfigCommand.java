package org.ccipstest.cli;

import org.ccipstest.app.*;
import org.ccipstest.rest.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.netconf.NetconfSession;


@Service
@Command(scope = "onos", name = "edit-netconf-config", description = "Edit Netconf configuration")
public class EditNetconfConfigCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "reqDTO", description = "Request DTO", required = true, multiValued = false)
    AppWebResource.RequestDTO reqDTO;

    @Override
    protected void doExecute() throws Exception {
        try {
            request req = AppWebResource.RequestDTO.transformToRequest(reqDTO);
            String uri_device_1 = "netconf:" + req.getNodes()[0].getIpControl() + ":830";
            String uri_device_2 = "netconf:" + req.getNodes()[1].getIpControl() + ":830";
            DeviceId new_device_1 = DeviceId.deviceId(uri_device_1);
            DeviceId new_device_2 = DeviceId.deviceId(uri_device_2);
            NetconfSession newDeviceSession_1 = StorageHandler.controller.getNetconfDevice(new_device_1).getSession();
            NetconfSession newDeviceSession_2 = StorageHandler.controller.getNetconfDevice(new_device_2).getSession();
            StorageHandler.createHandler(req, newDeviceSession_1, newDeviceSession_2);
            print("Netconf configuration edited successfully.");
        } catch (Exception e) {
            print("Error editing Netconf config: " + e.getMessage());
        }
    }
}
