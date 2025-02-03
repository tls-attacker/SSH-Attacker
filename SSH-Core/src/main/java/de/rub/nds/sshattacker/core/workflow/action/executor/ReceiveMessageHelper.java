/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action.executor;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.layer.PacketLayerParseResult;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.DisconnectMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.tlsattacker.transport.TransportHandler;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** A helper class to receive and process bytes from transport handler. */
public final class ReceiveMessageHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private ReceiveMessageHelper() {
        super();
    }

    /**
     * Receives and handles messages from the underlying transport handler.
     *
     * @param context The SSH context
     * @return A message action result containing the received packets and messages
     */
    @SuppressWarnings("UnusedReturnValue")
    public static MessageActionResult receiveMessages(SshContext context) {
        return receiveMessages(context, new LinkedList<>());
    }

    /**
     * Receives and handles messages from the underlying transport handler.
     *
     * @param context The SSH context
     * @param expectedMessages A list of expected messages
     * @return A message action result containing the received packets and messages
     */
    public static MessageActionResult receiveMessages(
            SshContext context, List<ProtocolMessage<?>> expectedMessages) {
        MessageActionResult result = new MessageActionResult();
        try {
            byte[] receivedBytes;
            int receivedBytesLength = 0;
            boolean shouldContinue = true;
            do {
                receivedBytes = receiveBytes(context);
                receivedBytesLength += receivedBytes.length;
                MessageActionResult tempResult = handleReceivedBytes(context, receivedBytes);
                result = result.merge(tempResult);
                if (context.getConfig().isQuickReceive() && !expectedMessages.isEmpty()) {
                    shouldContinue =
                            testShouldContinueReceiving(
                                    context, expectedMessages, tempResult.getMessageList());
                }
                if (receivedBytesLength >= context.getConfig().getReceiveMaximumBytes()) {
                    shouldContinue = false;
                }
            } while (receivedBytes.length != 0 && shouldContinue);
        } catch (IOException e) {
            LOGGER.warn(
                    "Received an IOException while fetching data from socket: {}",
                    e.getLocalizedMessage());
            LOGGER.debug(e);
            context.setReceivedTransportHandlerException(true);
        }
        return result;
    }

    /**
     * Receives bytes from the underlying transport handler.
     *
     * @param context The SSH context
     * @return An array of bytes received from the transport handler
     * @throws IOException Thrown by the underlying transport handler if receiving failed
     */
    public static byte[] receiveBytes(SshContext context) throws IOException {
        if (context.isReceiveAsciiModeEnabled()) {
            byte[] readByte;
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            TransportHandler transportHandler = context.getTransportHandler();
            do {
                readByte = transportHandler.fetchData(1);
                outputStream.write(readByte);
            } while (readByte.length > 0 && readByte[0] != CharConstants.NEWLINE);
            return outputStream.toByteArray();
        } else {
            return context.getTransportHandler().fetchData();
        }
    }

    /**
     * Receives additional bytes from the underlying transport handler. In contrast to
     * receiveBytes() this method will return an empty array instead of throwing an IOException.
     *
     * @param context The SSH context
     * @return An array of bytes received from the transport handler
     */
    private static byte[] receiveAdditionalBytes(SshContext context) {
        try {
            return receiveBytes(context);
        } catch (IOException e) {
            LOGGER.warn("Could not receive more bytes", e);
            context.setReceivedTransportHandlerException(true);
        }
        return new byte[0];
    }

    /**
     * Handles received bytes by parsing them into packets and consecutively messages.
     *
     * @param context The SSH context
     * @param receivedBytes Received bytes to handle
     * @return A MessageActionResult containing the parsed packets and messages
     */
    public static MessageActionResult handleReceivedBytes(
            SshContext context, byte[] receivedBytes) {
        if (receivedBytes.length == 0) {
            return new MessageActionResult();
        }

        int dataPointer = 0;
        LinkedList<AbstractPacket> retrievedPackets = new LinkedList<>();
        LinkedList<ProtocolMessage<?>> parsedMessages = new LinkedList<>();
        do {
            PacketLayerParseResult parseResult = parsePacket(context, receivedBytes, dataPointer);
            Optional<AbstractPacket> parsedPacket = parseResult.getParsedPacket();
            if (parsedPacket.isPresent()) {
                ProtocolMessage<?> message = context.getMessageLayer().parse(parsedPacket.get());
                message.adjustContext(context);
                retrievedPackets.add(parsedPacket.get());
                parsedMessages.add(message);

                if (message instanceof ChannelDataMessage) {
                    // Parse ChannelDataMessage
                    ProtocolMessage<?> innerMessage =
                            context.getDataMessageLayer().parse((ChannelDataMessage) message);
                    innerMessage.adjustContext(context);
                    parsedMessages.add(innerMessage);
                }
            }
            dataPointer += parseResult.getParsedByteCount();
        } while (dataPointer < receivedBytes.length);
        return new MessageActionResult(
                new ArrayList<>(retrievedPackets), new ArrayList<>(parsedMessages));
    }

    /**
     * Parses the given bytes into AbstractPackets. If parsing fails, the method will try to receive
     * additional bytes from the underlying transport handler. If no additional bytes are available
     * or an IOException occurs, bytes will be parsed softly (most likely to BlobPackets) by the
     * packet layer.
     *
     * @param context The SSH context
     * @param packetBytes Raw packet bytes to parse
     * @param startPosition Start position for parsing
     * @return The parse result from the underlying packet layer containing the total number of
     *     bytes parsed as well as the parsed packet itself
     */
    private static PacketLayerParseResult parsePacket(
            SshContext context, byte[] packetBytes, int startPosition) {
        try {
            return context.getPacketLayer().parsePacket(packetBytes, startPosition);
        } catch (ParserException e) {
            LOGGER.debug(e);
            if (context.getTransportHandler() != null) {
                LOGGER.debug(
                        "Could not parse the provided bytes into packets. Waiting for more data to become available");
                byte[] extraBytes = receiveAdditionalBytes(context);
                if (extraBytes != null && extraBytes.length > 0) {
                    return parsePacket(
                            context,
                            ArrayConverter.concatenate(packetBytes, extraBytes),
                            startPosition);
                }
            }
            LOGGER.debug("Did not receive more bytes. Parsing records softly");
            return context.getPacketLayer().parsePacketSoftly(packetBytes, startPosition);
        }
    }

    /**
     * Tests if receiving should continue based on a list of expected and received messages. Will
     * return false if either a DisconnectMessage (and isStopReceivingAfterDisconnect() flag is set
     * in config) or every expected message was received.
     *
     * @param context The SSH context containing the Config object
     * @param expectedMessages List of expected messages
     * @param receivedMessages List of received messages
     * @return True, if receiving should continue. False otherwise.
     */
    private static boolean testShouldContinueReceiving(
            SshContext context,
            List<ProtocolMessage<?>> expectedMessages,
            List<ProtocolMessage<?>> receivedMessages) {
        boolean receivedDisconnect =
                receivedMessages.stream().anyMatch(message -> message instanceof DisconnectMessage);
        if (receivedDisconnect && context.getConfig().isStopReceivingAfterDisconnect()) {
            return false;
        }
        return isExpectedMessageMissing(expectedMessages, receivedMessages);
    }

    /**
     * Checks if for each expected message there is a received message.
     *
     * @param expectedMessages List of expected messages
     * @param receivedMessages List of received messages
     * @return A boolean value indicating whether an expected message is missing
     */
    private static boolean isExpectedMessageMissing(
            List<ProtocolMessage<?>> expectedMessages, List<ProtocolMessage<?>> receivedMessages) {
        ArrayList<ProtocolMessage<?>> unmatchedMessages = new ArrayList<>(receivedMessages);
        for (ProtocolMessage<?> expectedMessage : expectedMessages) {
            ProtocolMessage<?> matchingMessage =
                    unmatchedMessages.stream()
                            .filter(
                                    message ->
                                            message.getClass().equals(expectedMessage.getClass()))
                            .findAny()
                            .orElse(null);
            if (matchingMessage == null) {
                return true;
            }
            unmatchedMessages.remove(matchingMessage);
        }
        return false;
    }
}
