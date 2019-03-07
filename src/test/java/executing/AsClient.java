package executing;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.constants.KeyExchangeAlgorithm;
import de.rub.nds.sshattacker.constants.Language;
import de.rub.nds.sshattacker.constants.MACAlgorithm;
import de.rub.nds.sshattacker.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveOverFp;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurveSECP256R1;
import de.rub.nds.sshattacker.imported.ec_.FieldElementFp;
import de.rub.nds.sshattacker.imported.ec_.Point;
import de.rub.nds.sshattacker.protocol.helper.ReceiveMessageHelper;
import de.rub.nds.sshattacker.protocol.helper.SendMessageHelper;
import de.rub.nds.sshattacker.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.message.ClientInitMessage;
import de.rub.nds.sshattacker.protocol.message.ECDHKeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.protocol.message.NewKeysMessage;
import de.rub.nds.sshattacker.protocol.parser.ClientInitMessageParser;
import de.rub.nds.sshattacker.protocol.preparator.ClientInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.ECDHKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.KeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.ClientInitMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.KeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.state.Chooser;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.Test;

public class AsClient {

    @Test
    public void main() throws Exception {
        BinaryPacketLayer binaryPacketLayer = new BinaryPacketLayer();
        MessageLayer messageLayer = new MessageLayer();

        SshContext context = new SshContext();
        context.setChooser(new Chooser(context));

        // TODO move transporthandler to Protocol-Attacker
        TransportHandler transport = new ClientTcpTransportHandler(2000, "localhost", 65222);
        transport.initialize();
        context.setBinaryPacketLayer(binaryPacketLayer);
        context.setMessageLayer(messageLayer);
        context.setTransportHandler(transport);

        SendMessageHelper sendMessageHelper = new SendMessageHelper();
        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

        context.setClientVersion("SSH-2.0-OpenSSH_7.8");

        context.setClientCookie(ArrayConverter.hexStringToByteArray("00000000000000000000000000000000"));
        context.setClientSupportedKeyExchangeAlgorithms(Arrays.asList(KeyExchangeAlgorithm.ecdh_sha2_nistp256));
        context.setClientSupportedHostKeyAlgorithms(Arrays.asList(PublicKeyAuthenticationAlgorithm.ssh_rsa));
        context.setClientSupportedCipherAlgorithmsClientToServer(Arrays.asList(EncryptionAlgorithm.aes128_cbc));
        context.setClientSupportedCipherAlgorithmsServerToClient(Arrays.asList(EncryptionAlgorithm.aes128_cbc));
        context.setClientSupportedMacAlgorithmsClientToServer(Arrays.asList(MACAlgorithm.hmac_sha1));
        context.setClientSupportedMacAlgorithmsServerToClient(Arrays.asList(MACAlgorithm.hmac_sha1));
        context.setClientSupportedCompressionAlgorithmsClientToServer(Arrays.asList(CompressionAlgorithm.none));
        context.setClientSupportedCompressionAlgorithmsServerToClient(Arrays.asList(CompressionAlgorithm.none));
        context.setClientSupportedLanguagesClientToServer(Arrays.asList(Language.none));
        context.setClientSupportedLanguagesServerToClient(Arrays.asList(Language.none));
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
        context.setClientEcdhPublicKey(Converter.concatenate(new byte[]{04}, x, y));
        ClientInitMessage clientInit = new ClientInitMessage();
        new ClientInitMessagePreparator(context, clientInit).prepare();

        context.appendToExchangeHashInput(clientInit.getVersion().getValue().getBytes());
        byte[] toSend = new ClientInitMessageSerializer(clientInit).serialize();

        transport.sendData(toSend);

        byte[] response = transport.fetchData();

        ClientInitMessage serverInit = new ClientInitMessageParser(0, response).parse();
        serverInit.getHandler(context).handle(serverInit);

        KeyExchangeInitMessage clientKeyInit = new KeyExchangeInitMessage();
        new KeyExchangeInitMessagePreparator(context, clientKeyInit).prepare();

        context.appendToExchangeHashInput(new KeyExchangeInitMessageSerializer(clientKeyInit).serialize());

        sendMessageHelper.sendMessages(Arrays.asList(clientKeyInit), context);
        receiveMessageHelper.receiveMessages(context);

        ECDHKeyExchangeInitMessage ecdhInit = new ECDHKeyExchangeInitMessage();
        new ECDHKeyExchangeInitMessagePreparator(context, ecdhInit).prepare();

        sendMessageHelper.sendMessages(Arrays.asList(ecdhInit), context);
        receiveMessageHelper.receiveMessages(context);

        sendMessageHelper.sendMessages(Arrays.asList(new NewKeysMessage()), context);

        BinaryPacket bp = new BinaryPacket(new byte[]{0, 1, 2, 3, 4, 5});
        bp.computePaddingLength((byte) 0);
        bp.generatePadding();
        bp.computePacketLength();
        Thread.sleep(2000);
    }
}
