package org.ccipstest.cli;

import org.ccipstest.app.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.onosproject.cli.AbstractShellCommand;


@Service
@Command(scope = "onos", name = "stop-tunnel", description = "Stop tunnel")
public class StopTunnelCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "name", description = "Tunnel name", required = false, multiValued = false)
    String name = null;

    @Argument(index = 1, name = "reqId", description = "Request ID", required = false, multiValued = false)
    String reqId = null;

    @Override
    protected void doExecute() throws Exception {
        try {
            StorageHandler.stopTunnel(name, reqId);
            print("Tunnel stopped successfully.");
        } catch (Exception e) {
            print("Error stopping tunnel: " + e.getMessage());
        }
    }
}