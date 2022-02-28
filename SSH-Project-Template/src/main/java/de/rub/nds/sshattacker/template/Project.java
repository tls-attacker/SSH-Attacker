/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.template;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;

public class Project {
    public static void main(String[] args) {
        Config config = new Config();
        config.setWorkflowTraceType(WorkflowTraceType.KEYEXCHANGE);
        config.getDefaultClientConnection().setHostname("localhost");
        config.getDefaultClientConnection().setPort(2222);
        // config.setUsername("marcus");
        WorkflowTrace trace = new WorkflowTrace();
        trace.addSshAction(new ReceiveAction(new VersionExchangeMessage()));
        State state = new State(config, trace);
        System.out.println(state.getConfig().getDefaultClientConnection().toString());
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);
        workflowExecutor.executeWorkflow();
        System.out.println("Trace:" + state.getWorkflowTrace().toString());
        System.out.println("Received Finished:" + WorkflowTraceUtil.getAllReceivedMessages(trace));
        System.out.println("Server Version: " + state.getSshContext().getServerVersion());
    }
}
