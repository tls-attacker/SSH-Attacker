/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.util;

import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.core.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.action.result.MessageActionResult;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public void sendBinaryPacket(BinaryPacket bp, SshContext context) throws IOException {
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();

        byte[] data;
        if ((context.isClient() && context.isClientToServerEncryptionActive())
                || (context.isServer() && context.isServerToClientEncryptionActive())) {
            CryptoLayer cryptoLayer =
                    context.isClient()
                            ? context.getCryptoLayerClientToServer()
                            : context.getCryptoLayerServerToClient();
            data = cryptoLayer.encryptPacket(bp);
        } else {
            data = binaryPacketLayer.serializeBinaryPacket(bp);
        }
        transportHandler.sendData(data);
    }

    public MessageActionResult sendMessage(Message<?> msg, SshContext context) {
        MessageLayer messageLayer = context.getMessageLayer();

        try {
            BinaryPacket binaryPacket = messageLayer.serializeMessage(msg);
            sendBinaryPacket(binaryPacket, context);
            context.incrementSequenceNumber();
            return new MessageActionResult(
                    Collections.singletonList(binaryPacket), Collections.singletonList(msg));
        } catch (IOException e) {
            LOGGER.warn("Error while sending packet: " + e.getMessage());
            return new MessageActionResult();
        }
    }

    public MessageActionResult sendMessages(List<Message<?>> list, SshContext context) {
        MessageActionResult result = new MessageActionResult();
        for (Message<?> msg : list) {
            if (msg instanceof VersionExchangeMessage) {
                result = sendVersionExchangeMessage((VersionExchangeMessage) msg, context);
            } else {
                result = result.merge(sendMessage(msg, context));
            }
        }
        return result;
    }

    // TODO dummy
    public MessageActionResult sendMessages(
            List<Message<?>> messageList, List<BinaryPacket> binaryPackets, SshContext context) {
        return sendMessages(messageList, context);
    }

    public MessageActionResult sendVersionExchangeMessage(
            VersionExchangeMessage msg, SshContext context) {
        TransportHandler transport = context.getTransportHandler();
        try {
            transport.sendData(msg.getSerializer().serialize());
        } catch (IOException e) {
            LOGGER.debug("Error while sending VersionExchangeMessage to remote: " + e.getMessage());
        }

        return new MessageActionResult(new LinkedList<>(), Collections.singletonList(msg));
    }
}
