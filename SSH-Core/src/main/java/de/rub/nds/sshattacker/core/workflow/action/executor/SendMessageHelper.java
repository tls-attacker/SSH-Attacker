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
import java.io.IOException;
import java.util.Collections;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Helper class for sending messages.
 *
 * @see MessageActionResult
 */
public final class SendMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private SendMessageHelper() {
        super();
    }

    /**
     * Sends the given packet.
     *
     * @param context the SSH context
     * @param packet the packet to send
     * @throws IOException if an I/O error occurs
     */
    public static void sendPacket(SshContext context, AbstractPacket packet) throws IOException {
        sendPacket(context, packet, false);
    }

    /**
     * Sends the given packet.
     *
     * @param context the SSH context
     * @param packet the packet to send
     * @param skipTransport if set to true, the resulting bytes of the binary packet will not be
     *     sent to the remote peer. This is useful for updating the SSH context and the binary
     *     packet protocol state without actually sending the packet.
     * @throws IOException if an I/O error occurs
     */
    public static void sendPacket(SshContext context, AbstractPacket packet, boolean skipTransport)
            throws IOException {
        AbstractPacketLayer packetLayer = context.getPacketLayer();
        TransportHandler transportHandler = context.getTransportHandler();
        byte[] packetBytes = packetLayer.preparePacket(packet);
        if (!skipTransport) {
            transportHandler.sendData(packetBytes);
        }
    }

    /**
     * Sends the given message and returns a {@link MessageActionResult} containing the sent packet
     * and message.
     *
     * @param context the SSH context
     * @param message the message to send
     * @return the {@link MessageActionResult}
     */
    public static MessageActionResult sendMessage(SshContext context, ProtocolMessage<?> message) {
        return sendMessage(context, message, false);
    }

    /**
     * Sends the given message and returns a {@link MessageActionResult} containing the sent packet
     * and message.
     *
     * @param context the SSH context
     * @param message the message to send
     * @param skipTransport if set to true, the resulting bytes of the message will not be sent to
     *     the remote peer. This is useful for updating the SSH context and the binary packet
     *     protocol state without actually sending the message.
     * @return the {@link MessageActionResult}
     */
    public static MessageActionResult sendMessage(
            SshContext context, ProtocolMessage<?> message, boolean skipTransport) {
        MessageLayer messageLayer = context.getMessageLayer();
        try {
            AbstractPacket packet = messageLayer.serialize(message);
            sendPacket(context, packet, skipTransport);
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

    /**
     * Sends the given messages and returns a {@link MessageActionResult} containing the sent packet
     * and messages.
     *
     * @param context the SSH context
     * @param messageStream the messages to send
     * @return the {@link MessageActionResult}
     */
    public static MessageActionResult sendMessages(
            SshContext context, Stream<ProtocolMessage<?>> messageStream) {
        return sendMessages(context, messageStream, false);
    }

    /**
     * Sends the given messages and returns a {@link MessageActionResult} containing the sent
     * packets and messages.
     *
     * @param context the SSH context
     * @param messageStream the messages to send
     * @param skipTransport if set to true, the resulting bytes of the binary packet will not be
     *     sent to the remote peer. This is useful for updating the SSH context and the binary
     *     packet protocol state without actually sending the packet.
     * @return the {@link MessageActionResult}
     */
    public static MessageActionResult sendMessages(
            SshContext context, Stream<ProtocolMessage<?>> messageStream, boolean skipTransport) {
        return messageStream
                .map(message -> sendMessage(context, message, skipTransport))
                .reduce(MessageActionResult::merge)
                .orElse(new MessageActionResult());
    }
}
