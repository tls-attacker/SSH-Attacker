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
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
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

            if (message instanceof DataMessage<?>) {
                // Serialize data message to ChannelDataMessage
                if (message instanceof HasSentHandler) {
                    ((HasSentHandler) message).adjustContextAfterSent(context);
                }
                // TODO: decide if we should pass prepareBeforeSending

                // serialize also prepares the ChannelDataMessage
                ChannelDataMessage messageWrapper =
                        context.getDataMessageLayer().serialize((DataMessage<?>) message);
                ((DataMessage<?>) message).setChannelDataWrapper(messageWrapper);
                message = messageWrapper;
            }

            AbstractPacket packet = context.getMessageLayer().serialize(message);
            sendPacket(context, packet);
            if (message instanceof HasSentHandler) {
                ((HasSentHandler) message).adjustContextAfterSent(context);
            }
            ArrayList<AbstractPacket> packetList = new ArrayList<>(1);
            packetList.add(packet);
            ArrayList<ProtocolMessage<?>> messageList;

            messageList = new ArrayList<>(1);
            messageList.add(message);
            return new MessageActionResult(packetList, messageList);
        } catch (IOException e) {
            LOGGER.warn("Error while sending packet: {}", e.getMessage());
            context.setReceivedTransportHandlerException(true);
            return new MessageActionResult();
        }
    }

    public static MessageActionResult sendMessages(
            SshContext context,
            ArrayList<ProtocolMessage<?>> messages,
            boolean prepareBeforeSending) {
        LinkedList<MessageActionResult> sendResults = new LinkedList<>();
        for (ProtocolMessage<?> message : messages) {
            sendResults.add(sendMessage(context, message, prepareBeforeSending));
        }
        return new MessageActionResult(sendResults);
    }
}
