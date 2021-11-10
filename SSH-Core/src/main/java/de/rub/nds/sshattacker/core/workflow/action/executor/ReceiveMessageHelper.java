/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.layer.MessageLayer;
import de.rub.nds.sshattacker.core.protocol.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.protocol.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    public MessageActionResult receiveMessages(SshContext context) {
        TransportHandler transportHandler = context.getTransportHandler();
        AbstractPacketLayer packetLayer = context.getPacketLayer();
        MessageLayer messageLayer = context.getMessageLayer();

        try {
            byte[] data = transportHandler.fetchData();
            LOGGER.trace("Received Data: " + ArrayConverter.bytesToRawHexString(data));

            if (data.length == 0) {
                LOGGER.debug(
                        "Tried to retrieve data from the transport handler but no data was available");
                return new MessageActionResult();
            }

            List<AbstractPacket> retrievedPackets = new LinkedList<>();
            try {
                retrievedPackets = packetLayer.parsePackets(data).collect(Collectors.toList());
            } catch (ParserException | CryptoException e) {
                LOGGER.warn(
                        "Unable to parse packet from bytes, continuing with the returned packets",
                        e);
            }

            Stream<? extends ProtocolMessage<?>> retrievedMessagesStream =
                    retrievedPackets.stream()
                            .map(messageLayer::parse)
                            .peek(message -> message.getHandler(context).adjustContext());
            return new MessageActionResult(
                    retrievedPackets, retrievedMessagesStream.collect(Collectors.toList()));
        } catch (IOException e) {
            LOGGER.debug("Caught an IOException while trying to retrieve incoming messages", e);
            return new MessageActionResult();
        }
    }

    // TODO[important!] dummy method until expectedMessages are used
    public MessageActionResult receiveMessages(
            SshContext context, List<ProtocolMessage<?>> expectedMessages) {
        return receiveMessages(context);
    }
}
