/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package executing;

import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.util.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.protocol.util.SendMessageHelper;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.executor.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class NetcatWorkflowFactory {

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

        SendMessageHelper sendMessageHelper = new SendMessageHelper();
        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        // noinspection InfiniteLoopStatement
        while (true) {
            // noinspection BusyWait
            Thread.sleep(5000);
            receiveMessageHelper.receiveMessages(state.getSshContext());
            String read = in.readLine();
            ChannelDataMessage dataMessage = new ChannelDataMessage();
            dataMessage.setRecipientChannel(0);
            dataMessage.setData((read + "\n").getBytes());
            sendMessageHelper.sendMessage(dataMessage, state.getSshContext());
        }
    }
}
