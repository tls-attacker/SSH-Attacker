/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package executing;

import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPasswordMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenSessionMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.NewKeysMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class NetcatWorkflow {

    // integration test
    public static void main(String[] args) throws Exception {

        State state = new State();
        WorkflowTrace trace = new WorkflowTrace();

        SendAction sendClientInit = new SendAction("client", new VersionExchangeMessage());
        trace.addSshAction(sendClientInit);
        trace.addSshAction(new ReceiveAction("client"));

        SendAction sendKex = new SendAction("client", new KeyExchangeInitMessage());
        ReceiveAction receiveKex = new ReceiveAction("client");
        trace.addSshAction(sendKex);
        trace.addSshAction(receiveKex);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        SendAction sendEcdhKex = new SendAction("client", ecdhInit);
        ReceiveAction receiveEcdhKex = new ReceiveAction("client");
        trace.addSshAction(sendEcdhKex);
        trace.addSshAction(receiveEcdhKex);
        SendAction sendNewKeys = new SendAction("client", new NewKeysMessage());
        trace.addSshAction(sendNewKeys);
        trace.addSshAction(new ActivateEncryptionAction());

        SendAction sendServiceRequest = new SendAction("client", new ServiceRequestMessage());
        ReceiveAction receiveServiceRequestResponse = new ReceiveAction("client");
        trace.addSshAction(sendServiceRequest);
        trace.addSshAction(receiveServiceRequestResponse);

        SendAction sendUserauthRequest = new SendAction("client", new UserAuthPasswordMessage());
        ReceiveAction receiveUserauthRequestResponse = new ReceiveAction("client");
        ReceiveAction receiveGlobalRequest = new ReceiveAction("client");
        trace.addSshActions(sendUserauthRequest);
        trace.addSshAction(receiveUserauthRequestResponse);
        trace.addSshAction(receiveGlobalRequest);

        SendAction sendSessionOpen = new SendAction("client", new ChannelOpenSessionMessage());
        ReceiveAction receiveSessionOpen = new ReceiveAction("client");
        trace.addSshAction(sendSessionOpen);
        trace.addSshAction(receiveSessionOpen);

        SendAction sendChannelRequest = new SendAction("client", new ChannelRequestExecMessage());
        ReceiveAction receiveChannelResponse = new ReceiveAction("client");
        trace.addSshAction(sendChannelRequest);
        trace.addSshAction(receiveChannelResponse);

        state.setWorkflowTrace(trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        state.getConfig().setWorkflowExecutorShouldClose(false);
        executor.executeWorkflow();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        // noinspection InfiniteLoopStatement
        while (true) {
            // noinspection BusyWait
            Thread.sleep(5000);
        }
    }
}
