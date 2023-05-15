/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.layer.MessageLayer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Collections;
import java.util.stream.Stream;

public final class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private SendMessageHelper() {
        super();
    }

    public static void sendPacket(SshContext context, AbstractPacket packet) throws IOException {
        AbstractPacketLayer packetLayer = context.getPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();
        transportHandler.sendData(packetLayer.preparePacket(packet));
    }

    public static MessageActionResult sendMessage(SshContext context, ProtocolMessage<?> message) {
        MessageLayer messageLayer = context.getMessageLayer();
        try {
            AbstractPacket packet = messageLayer.serialize(message);
            sendPacket(context, packet);
            Handler<?> handler = message.getHandler(context);
            if (handler instanceof MessageSentHandler) {
                ((MessageSentHandler) handler).adjustContextAfterMessageSent();
            }
            return new MessageActionResult(
                    Collections.singletonList(packet), Collections.singletonList(message));
        } catch (IOException e) {
            LOGGER.warn("Error while sending packet: {}", e.getMessage());
            return new MessageActionResult();
        }
    }

    public static MessageActionResult sendMessages(
            SshContext context, Stream<ProtocolMessage<?>> messageStream) {
        return messageStream
                .map(message -> sendMessage(context, message))
                .reduce(MessageActionResult::merge)
                .orElse(new MessageActionResult());
    }
}
