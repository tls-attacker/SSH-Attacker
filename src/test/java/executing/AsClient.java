package executing;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MacAlgorithm;
import de.rub.nds.sshattacker.constants.MessageIDConstants;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
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
import de.rub.nds.sshattacker.protocol.message.UnknownMessage;
import de.rub.nds.sshattacker.protocol.message.UserauthPasswordMessage;
import de.rub.nds.sshattacker.protocol.preparator.ClientInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.Chooser;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class AsClient {

    // integration test
    public static void main(String[] args) throws Exception {
        BinaryPacketLayer binaryPacketLayer = new BinaryPacketLayer();

        SshContext context = new SshContext();
        context.setChooser(new Chooser(context));
        CryptoLayer cryptoLayer = new CryptoLayer(context);
        MessageLayer messageLayer = new MessageLayer(context);


        TransportHandler transport = new ClientTcpTransportHandler(2000, "localhost", 65222);
        context.setBinaryPacketLayer(binaryPacketLayer);
        context.setMessageLayer(messageLayer);
        context.setTransportHandler(transport);
        context.setCryptoLayer(cryptoLayer);

        SendMessageHelper sendMessageHelper = new SendMessageHelper();
        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

        context.setClientVersion("SSH-2.0-OpenSSH_7.8");

        context.setClientCookie(ArrayConverter.hexStringToByteArray("00000000000000000000000000000000"));
        context.setClientSupportedKeyExchangeAlgorithms(Arrays.asList(KeyExchangeAlgorithm.ECDH_SHA2_NISTP256));
        context.setClientSupportedHostKeyAlgorithms(Arrays.asList(PublicKeyAuthenticationAlgorithm.SSH_RSA));
        context.setClientSupportedCipherAlgorithmsClientToServer(Arrays.asList(EncryptionAlgorithm.AES128_CBC));
        context.setClientSupportedCipherAlgorithmsServerToClient(Arrays.asList(EncryptionAlgorithm.AES128_CBC));
        context.setClientSupportedMacAlgorithmsClientToServer(Arrays.asList(MacAlgorithm.HMAC_SHA1));
        context.setClientSupportedMacAlgorithmsServerToClient(Arrays.asList(MacAlgorithm.HMAC_SHA1));
        context.setClientSupportedCompressionAlgorithmsClientToServer(Arrays.asList(CompressionAlgorithm.NONE));
        context.setClientSupportedCompressionAlgorithmsServerToClient(Arrays.asList(CompressionAlgorithm.NONE));
        context.setClientSupportedLanguagesClientToServer(Arrays.asList(Language.NONE));
        context.setClientSupportedLanguagesServerToClient(Arrays.asList(Language.NONE));
        context.setClientFirstKeyExchangePacketFollows((byte) 0);
        context.setClientReserved(0);

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

        //TODO race condition occurs here, socket taking too long to respond
        receiveMessageHelper.receiveInitMessage(context);

        KeyExchangeInitMessage clientKeyInit = new KeyExchangeInitMessage();
        new KeyExchangeInitMessagePreparator(context, clientKeyInit).prepare();

        context.appendToExchangeHashInput(new KeyExchangeInitMessageSerializer(clientKeyInit).serialize());

        sendMessageHelper.sendMessages(Arrays.asList(clientKeyInit), context);
        receiveMessageHelper.receiveMessages(context);

        EcdhKeyExchangeInitMessage ecdhInit = new EcdhKeyExchangeInitMessage();
        new EcdhKeyExchangeInitMessagePreparator(context, ecdhInit).prepare();
        sendMessageHelper.sendMessages(Arrays.asList(ecdhInit), context);
        receiveMessageHelper.receiveMessages(context);

        sendMessageHelper.sendMessage(new NewKeysMessage(), context);
        context.setIsEncryptionActive(true);

        ServiceRequestMessage serviceRequest = new ServiceRequestMessage("ssh-userauth");
        sendMessageHelper.sendMessage(serviceRequest, context);
        receiveMessageHelper.receiveMessages(context);
        
        UserauthPasswordMessage userauthRequest = new UserauthPasswordMessage();
        userauthRequest.setUsername("sshattack");
        userauthRequest.setServicename("ssh-connection");
        userauthRequest.setExpectResponse((byte) 0);
        userauthRequest.setPassword("bydahirsch");
        
        sendMessageHelper.sendMessage(userauthRequest, context);
        receiveMessageHelper.receiveMessages(context);
        
        receiveMessageHelper.receiveMessages(context); // Server Global Request
        
        ChannelOpenMessage sessionOpen = new ChannelOpenMessage();
        sessionOpen.setChannelType("session");
        sessionOpen.setSenderChannel(1337);
        sessionOpen.setWindowSize(Integer.MAX_VALUE);
        sessionOpen.setPacketSize(Integer.MAX_VALUE);
        
        sendMessageHelper.sendMessage(sessionOpen, context);
        receiveMessageHelper.receiveMessages(context);
        
        ChannelRequestMessage netcat = new ChannelRequestMessage();
        netcat.setRecipientChannel(0);
        netcat.setRequestType("exec");
        netcat.setReplyWanted((byte) 0);
        netcat.setPayload(Converter.stringToLengthPrefixedString("nc -l -p 13370"));

        sendMessageHelper.sendMessage(netcat, context);
        receiveMessageHelper.receiveMessages(context);
        
        while (true){
            sendMessageHelper.sendMessage(new ChannelDataMessage(0, "Slept".getBytes()), context);
            receiveMessageHelper.receiveMessages(context);
            Thread.sleep(1000);
        }
//        Thread.sleep(60* 1000);
    }
}