package org.ccipstest.cli;

import org.ccipstest.app.*;
import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.onosproject.cli.AbstractShellCommand;

@Service
@Command(scope = "onos", name = "storage", description = "Show storage")
public class StorageCommand extends AbstractShellCommand {
    @Override
    protected void doExecute() throws Exception {
        print(StorageHandler.storage.toString());
    }
}