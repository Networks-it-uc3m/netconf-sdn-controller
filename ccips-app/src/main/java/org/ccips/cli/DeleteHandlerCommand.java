package org.ccips.cli;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.ccips.app.handler.StorageHandler;
import org.onosproject.cli.AbstractShellCommand;


@Service
@Command(scope = "onos", name = "delete-handler", description = "Delete handler by ID")
public class DeleteHandlerCommand extends AbstractShellCommand {
    @Argument(index = 0, name = "reqId", description = "Request ID", required = true, multiValued = false)
    String reqId = null;

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