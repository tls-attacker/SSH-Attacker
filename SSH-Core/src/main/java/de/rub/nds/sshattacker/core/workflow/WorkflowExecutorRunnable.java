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
import java.net.Socket;
import org.apache.logging.log4j.CloseableThreadContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Spawn a new workflow trace for incoming connection.
 *
 * <p>Experimental. Really just a starting point (it works, though ;)
 */
public class WorkflowExecutorRunnable implements Runnable {

    private static final Logger LOGGER = LogManager.getLogger();
    protected final Socket socket;
    protected final State globalState;
    protected final ThreadedServerWorkflowExecutor parent;

    public WorkflowExecutorRunnable(
            State globalState, Socket socket, ThreadedServerWorkflowExecutor parent) {
        this.globalState = globalState;
        this.socket = socket;
        this.parent = parent;
    }

    @Override
    public void run() {
        String loggingContextString =
                String.format("%s %s", socket.getLocalPort(), socket.getRemoteSocketAddress());
        // add local port and remote address onto logging thread context
        // see https://logging.apache.org/log4j/2.x/manual/thread-context.html
        try (final CloseableThreadContext.Instance ctc =
                CloseableThreadContext.push(loggingContextString)) {
            runInternal();
        } finally {
            parent.clientDone(socket);
        }
    }

    protected void runInternal() {
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

        initConnectionForState(state);
        SshContext context = state.getInboundSshContexts().get(0);

        LOGGER.info("Exectuting workflow for {} ({})", socket, context);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();
        LOGGER.info("Workflow execution done on {} ({})", socket, context);
    }

    protected void initConnectionForState(State state) {
        // Do this post state init only if you know what you are doing.
        SshContext context = state.getInboundSshContexts().get(0);
        AliasedConnection connection = context.getConnection();
        // getting the hostname is slow, so we just set the ip
        connection.setHostname(socket.getInetAddress().getHostAddress());
        connection.setIp(socket.getInetAddress().getHostAddress());
        connection.setPort(socket.getPort());
        ServerTcpTransportHandler th;
        th = new ServerTcpTransportHandler(connection, socket);
        context.setTransportHandler(th);
    }
}
