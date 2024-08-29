package org.ccips.cli;


import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "get-greeting", description = "Get hello world greeting")
public class GetGreetingCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() throws Exception {
        print("Hello, world");
    }
}