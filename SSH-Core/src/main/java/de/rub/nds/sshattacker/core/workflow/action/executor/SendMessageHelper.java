/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.sshattacker.core.data.DataMessage;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.layer.AbstractPacketLayer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

    public static MessageActionResult sendMessage(
            SshContext context, ProtocolMessage<?> message, boolean prepareBeforeSending) {
        try {
            // Prepare message
            if (prepareBeforeSending) {
                message.prepare(context.getChooser());
            }

            ProtocolMessage<?> innerMessage = null;
            if (message instanceof DataMessage<?>) {
                // Serialize data message to ChannelDataMessage
                innerMessage = message;
                Handler<?> handler = innerMessage.getHandler(context);
                if (handler instanceof MessageSentHandler) {
                    ((MessageSentHandler) handler).adjustContextAfterMessageSent();
                }
                // TODO: decide if we should pass prepareBeforeSending
                // serialize also prepares the ChannelDataMessage
                message = context.getDataMessageLayer().serialize((DataMessage<?>) message);
            }

            AbstractPacket packet = context.getMessageLayer().serialize(message);
            sendPacket(context, packet);
            Handler<?> handler = message.getHandler(context);
            if (handler instanceof MessageSentHandler) {
                ((MessageSentHandler) handler).adjustContextAfterMessageSent();
            }
            ArrayList<AbstractPacket> packetList = new ArrayList<>(1);
            packetList.add(packet);
            ArrayList<ProtocolMessage<?>> messageList;
            if (innerMessage != null) {
                messageList = new ArrayList<>(2);
                messageList.add(message);
                messageList.add(innerMessage);
                return new MessageActionResult(packetList, messageList);
            }

            messageList = new ArrayList<>(1);
            messageList.add(message);
            return new MessageActionResult(packetList, messageList);
        } catch (IOException e) {
            LOGGER.warn("Error while sending packet: {}", e.getMessage());
            return new MessageActionResult();
        }
    }

    public static MessageActionResult sendMessages(
            SshContext context,
            Stream<ProtocolMessage<?>> messageStream,
            boolean prepareBeforeSending) {
        return messageStream
                .map(message -> sendMessage(context, message, prepareBeforeSending))
                .reduce(MessageActionResult::merge)
                .orElse(new MessageActionResult());
    }
}
