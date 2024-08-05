package org.ccipstest.cli;
import org.onosproject.cli.AbstractShellCommand;
import org.ccipstest.app.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.api.action.Argument;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "get-ipsec-config", description = "Get IPSec Configuration by ID")
public class GetIpsecConfigCommand extends AbstractShellCommand {

    @Argument(index = 0, name = "id", description = "ID of the IPSec Configuration", required = true, multiValued = false)
    String id;

    @Override
    protected void doExecute() {
        try {
            Handler response = StorageHandler.storage.get(Long.parseLong(id));
            if (response == null) {
                print("Handler with reqId : " + id + " does not exist");
                return;
            }
            print(response.toString());
        } catch (Exception e) {
            print("Error getting tunnel information: " + e.getMessage());
        }
    }
}