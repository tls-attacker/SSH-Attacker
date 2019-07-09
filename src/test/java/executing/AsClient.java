package executing;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.config.Config;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveOverFp;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveSECP256R1;
import de.rub.nds.sshattacker.imported.ec_.FieldElementFp;
import de.rub.nds.sshattacker.imported.ec_.Point;
import de.rub.nds.sshattacker.protocol.helper.ReceiveMessageHelper;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
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
import de.rub.nds.sshattacker.state.Chooser;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.SecureRandom;

public class AsClient {

    // integration test
    public static void main(String[] args) throws Exception {
        SshContext context = new SshContext();

        BinaryPacketLayer binaryPacketLayer = new BinaryPacketLayer();
        context.setBinaryPacketLayer(binaryPacketLayer);

        context.setConfig(new Config());
        context.setChooser(new Chooser(context));
        CryptoLayer cryptoLayer = new CryptoLayer(context);
        context.setCryptoLayer(cryptoLayer);

        MessageLayer messageLayer = new MessageLayer(context);
        context.setMessageLayer(messageLayer);

        TransportHandler transport = new ClientTcpTransportHandler(2000, "localhost", 65222);
        context.setTransportHandler(transport);

        SendMessageHelper sendMessageHelper = new SendMessageHelper();
        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

        EllipticCurveOverFp secp256r1 = new EllipticCurveSECP256R1();

        SecureRandom random = new SecureRandom();
        byte[] clientEcdhSecretKey = new byte[32];
        random.nextBytes(clientEcdhSecretKey);
        FieldElementFp a = new FieldElementFp(new BigInteger(1, clientEcdhSecretKey), secp256r1.getBasePointOrder());

        context.setClientEcdhSecretKey(ArrayConverter.bigIntegerToByteArray(a.getData()));

        Point myPoint = secp256r1.mult(new BigInteger(1, context.getClientEcdhSecretKey()), secp256r1.getBasePoint());
        byte[] x = ArrayConverter.bigIntegerToByteArray(myPoint.getX().getData());
        byte[] y = ArrayConverter.bigIntegerToByteArray(myPoint.getY().getData());

        // 04 -> no point compression used
        context.setClientEcdhPublicKey(ArrayConverter.concatenate(new byte[]{04}, x, y));
        ClientInitMessage clientInit = new ClientInitMessage();
        new ClientInitMessagePreparator(context, clientInit).prepare();

        context.appendToExchangeHashInput(clientInit.getVersion().getValue().getBytes());

        transport.initialize();
        sendMessageHelper.sendInitMessage(clientInit, context);

        receiveMessageHelper.receiveInitMessage(context);

        KeyExchangeInitMessage clientKeyInit = new KeyExchangeInitMessage();
        new KeyExchangeInitMessagePreparator(context, clientKeyInit).prepare();

        context.appendToExchangeHashInput(new KeyExchangeInitMessageSerializer(clientKeyInit).serialize());

        sendMessageHelper.sendMessage(clientKeyInit, context);
        receiveMessageHelper.receiveMessages(context);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        new EcdhKeyExchangeInitMessagePreparator(context, ecdhInit).prepare();
        sendMessageHelper.sendMessage(ecdhInit, context);
        receiveMessageHelper.receiveMessages(context);

        sendMessageHelper.sendMessage(new NewKeysMessage(), context);
        context.setIsEncryptionActive(true);

        ServiceRequestMessage serviceRequest = new ServiceRequestMessage("ssh-userauth");
        sendMessageHelper.sendMessage(serviceRequest, context);
        receiveMessageHelper.receiveMessages(context);

        UserauthPasswordMessage userauthRequest = new UserauthPasswordMessage();
        new UserauthPasswordMessagePreparator(context, userauthRequest).prepare();

        sendMessageHelper.sendMessage(userauthRequest, context);
        receiveMessageHelper.receiveMessages(context);

        receiveMessageHelper.receiveMessages(context); // Server Global Request no idea what this is

        ChannelOpenMessage sessionOpen = new ChannelOpenMessage();
        new ChannelOpenMessagePreparator(context, sessionOpen).prepare();

        sendMessageHelper.sendMessage(sessionOpen, context);
        receiveMessageHelper.receiveMessages(context);

        ChannelRequestMessage netcat = new ChannelRequestMessage();
        new ChannelRequestMessagePreparator(context, netcat).prepare();

        sendMessageHelper.sendMessage(netcat, context);
        receiveMessageHelper.receiveMessages(context);

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while (true) {
            Thread.sleep(5000);
            receiveMessageHelper.receiveMessages(context);
            String read = in.readLine();
            sendMessageHelper.sendMessage(new ChannelDataMessage(0, (read + "\n").getBytes()), context);
        }
    }
}
