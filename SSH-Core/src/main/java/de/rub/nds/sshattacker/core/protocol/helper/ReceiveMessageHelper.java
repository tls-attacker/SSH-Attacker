/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.helper;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.layers.BinaryPacketLayer;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayer;
import de.rub.nds.sshattacker.core.protocol.layers.MessageLayer;
import de.rub.nds.sshattacker.core.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.core.protocol.message.VersionExchangeMessage;
import de.rub.nds.sshattacker.core.protocol.message.Message;
import de.rub.nds.sshattacker.core.protocol.parser.VersionExchangeMessageParser;
import de.rub.nds.sshattacker.core.workflow.action.result.MessageActionResult;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
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

        if (!context.isVersionExchangeComplete()) {
            MessageActionResult result = receiveVersionExchangeMessage(context);
            context.setVersionExchangeComplete(true);
            return result;
        } else {
            try {
                byte[] data = transportHandler.fetchData();
                if (data.length != 0) {

                    LOGGER.debug("Received Data: ");
                    LOGGER.debug(ArrayConverter.bytesToRawHexString(data));

                    // Response from server: Invalid SSH identification string.
                    if (Arrays.equals(data, ArrayConverter.hexStringToByteArray("496E76616C696420535348206964656E74696669636174696F6E20737472696E672E0D0A"))
                            || Arrays.equals(data, ArrayConverter.hexStringToByteArray("496E76616C696420535348206964656E74696669636174696F6E20737472696E672E"))) {
                        LOGGER.debug("Invalid identification string");
                        return new MessageActionResult(); // TODO implement fitting message
                    }

                    if((context.isClient() && context.isServerToClientEncryptionActive()) || (context.isServer() && context.isClientToServerEncryptionActive())) {
                        CryptoLayer cryptoLayer = context.isClient() ?
                                context.getCryptoLayerServerToClient() : context.getCryptoLayerClientToServer();
                        data = cryptoLayer.decryptBinaryPackets(data);
                    }

                    try {
                        List<BinaryPacket> binaryPackets = binaryPacketLayer.parseBinaryPackets(data);
                        List<Message<?>> messages = messageLayer.parseMessages(binaryPackets);
                        messages.forEach(message -> message.handleSelf(context));
                        return new MessageActionResult(binaryPackets, messages);
                    } catch (ParserException e) {
                        BinaryPacket dummyPacket = new BinaryPacket(data);
                        return new MessageActionResult(Collections.singletonList(dummyPacket), new LinkedList<>());
                    }
                } else {
                    LOGGER.debug("TransportHandler does not have data.");
                    return new MessageActionResult();
                }
            } catch (IOException e) {
                LOGGER.debug("Error while receiving Data " + e.getMessage());
                return new MessageActionResult();
            }
        }
    }

    // TODO dummy method until expectedMessages are used
    public MessageActionResult receiveMessages(List<Message<?>> expectedMessages, SshContext context) {
        return receiveMessages(context);
    }

    public MessageActionResult receiveVersionExchangeMessage(SshContext context) {
        TransportHandler transport = context.getTransportHandler();
        try {
            byte[] response = transport.fetchData();
            VersionExchangeMessage serverVersion = new VersionExchangeMessageParser(0, response).parse();
            serverVersion.handleSelf(context);
            return new MessageActionResult(new LinkedList<>(), Collections.singletonList(serverVersion));
        } catch (IOException e) {
            LOGGER.debug("Error while receiving VersionExchange from remote: " + e.getMessage());
            return new MessageActionResult();
        }
    }

}
