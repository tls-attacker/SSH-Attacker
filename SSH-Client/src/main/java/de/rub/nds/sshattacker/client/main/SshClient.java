/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.client.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.sshattacker.client.config.ClientCommandConfig;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public final class SshClient {

    private static final Logger LOGGER = LogManager.getLogger();

    private SshClient() {
        super();
    }

    public static void main(String[] args) {
        ClientCommandConfig config = new ClientCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(config);
        try {
            commander.parse(args);
            if (config.getGeneralDelegate().isHelp()) {
                commander.usage();
                return;
            }

            try {
                Config sshConfig = config.createConfig();
                startSshClient(sshConfig);
            } catch (Exception E) {
                LOGGER.error(
                        "Encountered an uncaught Exception aborting. See debug for more info.", E);
            }
        } catch (ParameterException E) {
            LOGGER.error("Could not parse provided parameters. {}", E.getLocalizedMessage());
            LOGGER.debug(E);
            commander.usage();
        }
    }

    public static void startSshClient(Config config) {
        State state = new State(config);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.warn(
                    "The SSH protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex.getLocalizedMessage(), ex);
        }
    }
}
