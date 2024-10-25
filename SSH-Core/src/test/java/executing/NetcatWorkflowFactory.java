/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package executing;

import de.rub.nds.modifiablevariable.util.Modifiable;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public final class NetcatWorkflowFactory {

    private NetcatWorkflowFactory() {
        super();
    }

    // integration test
    public static void main(String[] args) throws Exception {

        State state = new State();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(state.getConfig())
                        .createWorkflowTrace(WorkflowTraceType.FULL, RunningModeType.SERVER);

        state.setWorkflowTrace(trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        state.getConfig().setWorkflowExecutorShouldClose(false);
        executor.executeWorkflow();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        // noinspection InfiniteLoopStatement
        while (true) {
            // noinspection BusyWait
            Thread.sleep(5000);
            String read = in.readLine();
            ChannelDataMessage dataMessage = new ChannelDataMessage();
            dataMessage.setRecipientChannelId(Modifiable.explicit(0));
            dataMessage.setData((read + "\n").getBytes());
        }
    }
}
