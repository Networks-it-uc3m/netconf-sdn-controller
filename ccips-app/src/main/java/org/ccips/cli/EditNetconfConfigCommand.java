package org.ccips.cli;

import org.ccips.app.config.LifetimeConfig;
import org.ccips.app.config.Node;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.ccips.app.handler.StorageHandler;
import org.ccips.app.handler.request;
import org.onosproject.cli.AbstractShellCommand;
import org.onosproject.net.DeviceId;
import org.onosproject.netconf.NetconfSession;


@Service
@Command(scope = "onos", name = "edit-netconf-config", description = "Edit Netconf configuration")
public class EditNetconfConfigCommand extends AbstractShellCommand {


    @Argument(index = 0, name = "ipData1", description = "IP Data 1", required = true, multiValued = false)
    String ipData1;

    @Argument(index = 1, name = "ipControl1", description = "IP Control 1", required = true, multiValued = false)
    String ipControl1;

    @Argument(index = 2, name = "networkInternal1", description = "Network Internal 1", required = true, multiValued = false)
    String networkInternal1;

    @Argument(index = 3, name = "ipData2", description = "IP Data 2", required = true, multiValued = false)
    String ipData2;

    @Argument(index = 4, name = "ipControl2", description = "IP Control 2", required = true, multiValued = false)
    String ipControl2;

    @Argument(index = 5, name = "networkInternal2", description = "Network Internal 2", required = true, multiValued = false)
    String networkInternal2;

    @Argument(index = 6, name = "encAlg", description = "Encryption Algorithm", required = true, multiValued = false)
    String encAlg;

    @Argument(index = 7, name = "intalg", description = "Integrity Algorithm", required = true, multiValued = false)
    String intalg;

    @Argument(index = 8, name = "nBytesSoft", description = "Soft Byte Limit", required = true, multiValued = false)
    String nBytesSoft;

    @Argument(index = 9, name = "nPacketsSoft", description = "Soft Packet Limit", required = true, multiValued = false)
    String nPacketsSoft;

    @Argument(index = 10, name = "nTimeSoft", description = "Soft Time Limit", required = true, multiValued = false)
    String nTimeSoft;

    @Argument(index = 11, name = "nTimeIdleSoft", description = "Soft Idle Time Limit", required = true, multiValued = false)
    String nTimeIdleSoft;

    @Argument(index = 12, name = "nBytesHard", description = "Hard Byte Limit", required = true, multiValued = false)
    String nBytesHard;

    @Argument(index = 13, name = "nPacketsHard", description = "Hard Packet Limit", required = true, multiValued = false)
    String nPacketsHard;

    @Argument(index = 14, name = "nTimeHard", description = "Hard Time Limit", required = true, multiValued = false)
    String nTimeHard;

    @Argument(index = 15, name = "nTimeIdleHard", description = "Hard Idle Time Limit", required = true, multiValued = false)
    String nTimeIdleHard;

    @Override
    protected void doExecute() throws Exception {
        try {
            networkInternal1 = "null".equals(networkInternal1) ? null : networkInternal1;
            networkInternal2 = "null".equals(networkInternal2) ? null : networkInternal2;

            Node[] nodes = new Node[2];
            nodes[0] = new Node(networkInternal1, null, ipData1, ipControl1);
            nodes[1] = new Node(networkInternal2, null, ipData2, ipControl2);

            LifetimeConfig softLifetime = new LifetimeConfig(nBytesSoft, nPacketsSoft, nTimeSoft, nTimeIdleSoft);
            LifetimeConfig hardLifetime = new LifetimeConfig(nBytesHard, nPacketsHard, nTimeHard, nTimeIdleHard);

            request req = new request(nodes, encAlg, intalg, softLifetime, hardLifetime);

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
