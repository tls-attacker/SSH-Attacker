/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler;
import java.io.IOException;
import java.net.Socket;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Spawn a new workflow trace for incoming connection.
 *
 * <p>Experimental. Really just a starting point (it works, though ;)
 */
public class WorkflowExecutorRunnable implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Socket socket;
    private final State globalState;

    public WorkflowExecutorRunnable(State globalState, Socket socket) {
        super();
        this.globalState = globalState;
        this.socket = socket;
    }

    @Override
    public void run() {
        LOGGER.info("Spawning workflow on socket {}", socket);
        // Currently, WorkflowTraces cannot be copied with external modules
        // if they define custom actions. This is because copying relies
        // on serialization, and actions from other packages are unknown
        // to the WorkflowTrace/JAXB context (sigh).
        // General problem: external actions cannot be serialized.
        // This means that currently there are two possibilities:
        // Either the workflow trace is generated freshly (i.e. from the
        // factory), or all actions are known to the serialization context.
        // Future: a proper copy method would be very useful. The two
        // cases above are both very expensive tasks that should be avoided.
        WorkflowTrace localTrace = globalState.getWorkflowTraceCopy();

        // Note that a Config should never be changed by WorkflowTrace
        // execution. Let's hope this is true in practice ;)
        State state = new State(globalState.getConfig(), localTrace);

        // Do this post state init only if you know what you are doing.
        SshContext serverCtx = state.getInboundSshContexts().get(0);
        AliasedConnection serverCon = serverCtx.getConnection();
        serverCon.setHostname(socket.getInetAddress().getHostAddress());
        serverCon.setPort(socket.getLocalPort());
        ServerTcpTransportHandler th;
        try {
            th = new ServerTcpTransportHandler(serverCon, socket);
        } catch (IOException ex) {
            LOGGER.error("Could not prepare TransportHandler for {}", socket);
            LOGGER.error("Aborting workflow trace execution on {}", socket);
            return;
        }
        serverCtx.setTransportHandler(th);

        LOGGER.info("Executing workflow for {} ({})", socket, serverCtx);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Workflow execution done on {} ({})", socket, serverCtx);
    }
}
