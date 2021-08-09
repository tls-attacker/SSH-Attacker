/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.core.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.VersionExchangeMessageParser;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.action.result.MessageActionResult;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public MessageActionResult receiveMessages(SshContext context) {
        TransportHandler transportHandler = context.getTransportHandler();
        BinaryPacketLayer binaryPacketLayer = context.getBinaryPacketLayer();
        MessageLayer messageLayer = context.getMessageLayer();

        List<BinaryPacket> binaryPackets = new LinkedList<>();
        List<Message<?>> retrievedMessages = new LinkedList<>();

        try {
            byte[] data = transportHandler.fetchData();
            LOGGER.trace("Received Data: " + ArrayConverter.bytesToRawHexString(data));
            // TODO: We assume that if a version exchange message is present, it is the first
            // message within the data array - this is always true for the happy flow, but for
            // strange flows this may not hold
            if (data.length == 0) {
                LOGGER.debug(
                        "Tried to retrieve data from the transport handler but no data was available");
                return new MessageActionResult();
            } else if (new String(data, StandardCharsets.US_ASCII)
                    .startsWith("Invalid SSH identification string.")) {
                // TODO: Implement message for invalid SSH identification string
                LOGGER.warn(
                        "The server reported the identification string sent by the SSH-Attacker is invalid");
                return new MessageActionResult();
            } else if (new String(data, StandardCharsets.US_ASCII).startsWith("SSH-2.0")) {
                // Version exchange message retrieved
                VersionExchangeMessageParser peerVersionParser =
                        new VersionExchangeMessageParser(0, data);
                VersionExchangeMessage peerVersion = peerVersionParser.parse();
                retrievedMessages.add(peerVersion);
                context.setVersionExchangeComplete(true);
                // Skip parsed bytes of the data array (other binary packets might be directly
                // concatenated)
                data = Arrays.copyOfRange(data, peerVersionParser.getPointer(), data.length);
            }

            // Binary packet retrieved
            if ((context.isClient() && context.isServerToClientEncryptionActive())
                    || (context.isServer() && context.isClientToServerEncryptionActive())) {
                CryptoLayer cryptoLayer =
                        context.isClient()
                                ? context.getCryptoLayerServerToClient()
                                : context.getCryptoLayerClientToServer();
                data = cryptoLayer.decryptBinaryPackets(data);
            }

            try {
                binaryPackets.addAll(binaryPacketLayer.parseBinaryPackets(data));
                retrievedMessages.addAll(messageLayer.parseMessages(binaryPackets));
            } catch (ParserException e) {
                // TODO: Handle ParserException to distinguish invalid data from valid binary
                // packets
                binaryPackets.add(new BinaryPacket(data));
            }
            retrievedMessages.forEach(message -> message.handleSelf(context));
            return new MessageActionResult(binaryPackets, retrievedMessages);
        } catch (IOException e) {
            LOGGER.debug("Caught an IOException while trying to retrieve incoming messages", e);
            return new MessageActionResult();
        }
    }

    // TODO dummy method until expectedMessages are used
    public MessageActionResult receiveMessages(
            List<Message<?>> expectedMessages, SshContext context) {
        return receiveMessages(context);
    }
}
