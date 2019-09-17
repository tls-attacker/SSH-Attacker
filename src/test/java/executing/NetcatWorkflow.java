package executing;

import de.rub.nds.sshattacker.protocol.helper.ReceiveMessageHelper;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.message.ChannelDataMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.protocol.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.protocol.message.ServiceRequestMessage;
import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import de.rub.nds.sshattacker.protocol.preparator.ChannelOpenMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.ChannelRequestMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.ClientInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.UserauthPasswordMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.State;
import de.rub.nds.sshattacker.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.workflow.action.AppendToDigestAction;
import de.rub.nds.sshattacker.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.workflow.action.SendAction;
import de.rub.nds.sshattacker.workflow.executor.DefaultWorkflowExecutor;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class NetcatWorkflow {

    // integration test
    public static void main(String[] args) throws Exception {

        State state = new State();

        ClientInitMessage clientInit = new ClientInitMessage();
        new ClientInitMessagePreparator(state.getSshContext(), clientInit).prepare();
        clientInit.getVersion().createRandomModificationAtRuntime();

        WorkflowTrace trace = new WorkflowTrace();
        SendAction sendClientInit = new SendAction("defaultConnection", clientInit);
        AppendToDigestAction clientInitDigest = new AppendToDigestAction(clientInit.getVersion().getValue().getBytes());
        trace.addSshAction(clientInitDigest);
        trace.addSshAction(sendClientInit);
        ReceiveAction receiveServerInit = new ReceiveAction("defaultConnection");
        trace.addSshAction(receiveServerInit);

        KeyExchangeInitMessage clientKeyInit = new KeyExchangeInitMessage();
        new KeyExchangeInitMessagePreparator(state.getSshContext(), clientKeyInit).prepare();
        SendAction sendKex = new SendAction("defaultConnection", clientKeyInit);
        ReceiveAction receiveKex = new ReceiveAction("defaultConnection");
        AppendToDigestAction kexInitDigest = new AppendToDigestAction(new KeyExchangeInitMessageSerializer(clientKeyInit).serialize());
        trace.addSshAction(kexInitDigest);
        trace.addSshAction(sendKex);
        trace.addSshAction(receiveKex);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        new EcdhKeyExchangeInitMessagePreparator(state.getSshContext(), ecdhInit).prepare();
        SendAction sendEcdhKex = new SendAction("defaultConnection", ecdhInit);
        ReceiveAction receiveEcdhKex = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendEcdhKex);
        trace.addSshAction(receiveEcdhKex);
        NewKeysMessage newKeys = new NewKeysMessage();
        SendAction sendNewKeys = new SendAction("defaultConnection", newKeys);
        trace.addSshAction(sendNewKeys);
        trace.addSshAction(new ActivateEncryptionAction());

        ServiceRequestMessage serviceRequest = new ServiceRequestMessage("ssh-userauth");
        SendAction sendServiceRequest = new SendAction("defaultConnection", serviceRequest);
        ReceiveAction receiveServiceRequestResponse = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendServiceRequest);
        trace.addSshAction(receiveServiceRequestResponse);

        UserauthPasswordMessage userauthRequest = new UserauthPasswordMessage();
        new UserauthPasswordMessagePreparator(state.getSshContext(), userauthRequest).prepare();
        SendAction sendUserauthRequest = new SendAction("defaultConnection", userauthRequest);
        ReceiveAction receiveUserauthRequestResponse = new ReceiveAction("defaultConnection");
        ReceiveAction receiveGlobalRequest = new ReceiveAction("defaultConnection");
        trace.addSshActions(sendUserauthRequest);
        trace.addSshAction(receiveUserauthRequestResponse);
        trace.addSshAction(receiveGlobalRequest);

        ChannelOpenMessage sessionOpen = new ChannelOpenMessage();
        new ChannelOpenMessagePreparator(state.getSshContext(), sessionOpen).prepare();
        SendAction sendSessionOpen = new SendAction("defaultConnection", sessionOpen);
        ReceiveAction receiveSessionOpen = new ReceiveAction("defaultConnection");
        trace.addSshAction(sendSessionOpen);
        trace.addSshAction(receiveSessionOpen);

        ChannelRequestMessage netcat = new ChannelRequestMessage();
        new ChannelRequestMessagePreparator(state.getSshContext(), netcat).prepare();
        SendAction sendChannelRequest = new SendAction("defaultConnection", netcat);
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
        while (true) {
            Thread.sleep(5000);
            receiveMessageHelper.receiveMessages(state.getSshContext());
            String read = in.readLine();
            sendMessageHelper.sendMessage(new ChannelDataMessage(0, (read + "\n").getBytes()), state.getSshContext());
        }
    }
}
