/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package executing;

import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.util.ReceiveMessageHelper;
import de.rub.nds.sshattacker.core.protocol.util.SendMessageHelper;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.executor.DefaultWorkflowExecutor;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class NetcatWorkflow {

    // integration test
    public static void main(String[] args) throws Exception {

        State state = new State();
        WorkflowTrace trace = new WorkflowTrace();

        SendAction sendClientInit = new SendAction("defaultConnection", new VersionExchangeMessage());
        trace.addSshAction(sendClientInit);
        trace.addSshAction(new ReceiveAction("defaultConnection"));

        SendAction sendKex = new SendAction("defaultConnection", new KeyExchangeInitMessage());
        ReceiveAction receiveKex = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendKex);
        trace.addSshAction(receiveKex);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        SendAction sendEcdhKex = new SendAction("defaultConnection", ecdhInit);
        ReceiveAction receiveEcdhKex = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendEcdhKex);
        trace.addSshAction(receiveEcdhKex);
        SendAction sendNewKeys = new SendAction("defaultConnection", new NewKeysMessage());
        trace.addSshAction(sendNewKeys);
        trace.addSshAction(new ActivateEncryptionAction());

        SendAction sendServiceRequest = new SendAction("defaultConnection", new ServiceRequestMessage());
        ReceiveAction receiveServiceRequestResponse = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendServiceRequest);
        trace.addSshAction(receiveServiceRequestResponse);

        SendAction sendUserauthRequest = new SendAction("defaultConnection", new UserAuthPasswordMessage());
        ReceiveAction receiveUserauthRequestResponse = new ReceiveAction("defaultConnection");
        ReceiveAction receiveGlobalRequest = new ReceiveAction("defaultConnection");
        trace.addSshActions(sendUserauthRequest);
        trace.addSshAction(receiveUserauthRequestResponse);
        trace.addSshAction(receiveGlobalRequest);

        SendAction sendSessionOpen = new SendAction("defaultConnection", new ChannelOpenMessage());
        ReceiveAction receiveSessionOpen = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendSessionOpen);
        trace.addSshAction(receiveSessionOpen);

        SendAction sendChannelRequest = new SendAction("defaultConnection", new ChannelRequestExecMessage());
        ReceiveAction receiveChannelResponse = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendChannelRequest);
        trace.addSshAction(receiveChannelResponse);

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
        }
    }
}
