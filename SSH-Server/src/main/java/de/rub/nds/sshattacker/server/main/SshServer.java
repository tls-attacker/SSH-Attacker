/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.server.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.server.config.ServerCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SshServer {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) {
        ServerCommandConfig config = new ServerCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }

            Config sshConfig = config.createConfig();

            do {
                try {

                    SshServer server = new SshServer();
                    server.startSshServer(sshConfig);
                } catch (Exception e) {
                    LOGGER.error(
                            "Encountered an uncaught exception, aborting. See debug for more info.",
                            e);
                }
            } while (sshConfig.getEndless());
        } catch (ParameterException e) {
            LOGGER.error("Could not parse provided parameters: " + e.getLocalizedMessage());
            LOGGER.debug(e);
            commander.usage();
        }
    }

    public void startSshServer(Config config) {
        State state = new State(config);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            LOGGER.warn(
                    "The SSH protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(e.getLocalizedMessage(), e);
        }

        /*        try {
            if (!state.getSshContext().getTransportHandler().isClosed()) {
                state.getSshContext().getTransportHandler().closeConnection();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }*/
    }
}
