package org.ccipstest.cli;

import org.ccipstest.app.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.onosproject.cli.AbstractShellCommand;


@Service
@Command(scope = "onos", name = "delete-handler", description = "Delete handler by ID")
public class DeleteHandlerCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "reqId", description = "Request ID", required = true, multiValued = false)
    long reqId;

    @Override
    protected void doExecute() throws Exception {
        try {
            StorageHandler.deleteHandler(reqId);
            print("Handler deleted successfully.");
        } catch (Exception e) {
            print("Error deleting handler: " + e.getMessage());
        }
    }
}