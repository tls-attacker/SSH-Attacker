/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.mitm.main;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.ConfigurationException;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.WorkflowTraceSerializer;
import de.rub.nds.sshattacker.core.workflow.action.ProxyFilterMessagesAction;
import de.rub.nds.sshattacker.core.workflow.factory.SshActionFactory;
import de.rub.nds.sshattacker.mitm.config.MitmCommandConfig;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SshMitm implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String[] args;

    public SshMitm(String... args) {
        super();
        this.args = args;
    }

    public void run()
            throws ParameterException, WorkflowExecutionException, ConfigurationException {

        MitmCommandConfig cmdConfig = new MitmCommandConfig(new GeneralDelegate());
        JCommander commander = new JCommander(cmdConfig);

        try {
            commander.parse(args);
        } catch (ParameterException pe) {
            LOGGER.error("Could not parse provided parameters. {}", pe.getLocalizedMessage());
            LOGGER.info("Try -help");
            throw pe;
        }

        if (cmdConfig.getGeneralDelegate().isHelp()) {
            commander.usage();
            return;
        }

        try {
            Config config = cmdConfig.createConfig();
            config.setWorkflowExecutorShouldClose(false);

            WorkflowTrace trace = null;
            if (cmdConfig.getWorkflowInput() != null) {
                LOGGER.debug("Reading workflow trace from {}", cmdConfig.getWorkflowInput());
                trace =
                        WorkflowTraceSerializer.insecureRead(
                                new FileInputStream(cmdConfig.getWorkflowInput()));
            }
            State state = executeMitmWorkflow(config, trace);

            // From here, we simply repeat the two forward actions from the workflow.
            AliasedConnection inboundConnection = config.getDefaultServerConnection();
            AliasedConnection outboundConnection = config.getDefaultClientConnection();
            SshContext inboundContext = state.getSshContext(inboundConnection.getAlias());
            SshContext outboundContext = state.getSshContext(outboundConnection.getAlias());
            TransportHandler inboundTransportHandler = inboundContext.getTransportHandler();
            TransportHandler outboundTransportHandler = outboundContext.getTransportHandler();
            inboundTransportHandler.setTimeout(100);
            outboundTransportHandler.setTimeout(100);

            int maxCount = 1000;
            while (maxCount > 0) {
                boolean newMessages = false;
                ProxyFilterMessagesAction clientAction =
                        (ProxyFilterMessagesAction)
                                SshActionFactory.createProxyFilterMessagesAction(
                                        inboundConnection,
                                        outboundConnection,
                                        ConnectionEndType.CLIENT);
                ProxyFilterMessagesAction serverAction =
                        (ProxyFilterMessagesAction)
                                SshActionFactory.createProxyFilterMessagesAction(
                                        inboundConnection,
                                        outboundConnection,
                                        ConnectionEndType.SERVER);

                clientAction.execute(state);
                if (!clientAction.getReceivedMessages().isEmpty()) {
                    state.getWorkflowTrace().addSshAction(clientAction);
                    newMessages = true;
                }
                if (inboundTransportHandler.isClosed()
                        || inboundContext.isDisconnectMessageReceived()) {
                    // instead of breaking, close the client side of the server connection.
                    break;
                }
                serverAction.execute(state);
                if (!serverAction.getReceivedMessages().isEmpty()) {
                    state.getWorkflowTrace().addSshAction(serverAction);
                    newMessages = true;
                }
                if (outboundTransportHandler.isClosed()
                        || outboundContext.isDisconnectMessageReceived()) {
                    // instead of breaking, close the server side of the client connection.
                    break;
                }
                if (newMessages) {
                    maxCount = maxCount - 1;
                }
            }
            state.storeTrace();
        } catch (WorkflowExecutionException wee) {
            LOGGER.error(
                    "The SSH protocol flow was not executed completely. {} - See debug messages for more details.",
                    wee.getLocalizedMessage());
            LOGGER.error(wee.getLocalizedMessage());
            LOGGER.debug(wee);
            throw wee;
        } catch (ConfigurationException ce) {
            LOGGER.error(
                    "Encountered a ConfigurationException aborting. {} - See debug messages for more details.",
                    ce.getLocalizedMessage());
            LOGGER.debug(ce.getLocalizedMessage(), ce);
            throw ce;
        } catch (ParameterException pe) {
            LOGGER.error("Could not parse provided parameters. {}", pe.getLocalizedMessage());
            LOGGER.info("Try -help");
            throw pe;
        } catch (Exception E) {
            LOGGER.error(E);
        }
    }

    public static State executeMitmWorkflow(Config config, WorkflowTrace trace)
            throws ConfigurationException {
        LOGGER.debug("Creating and launching mitm.");
        State state;

        if (trace == null) {
            state = new State(config);
        } else {
            state = new State(config, trace);
        }
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        try {
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException e) {
            LOGGER.warn(
                    "The SSH protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(e.getLocalizedMessage(), e);
        }
        return state;
    }
}
