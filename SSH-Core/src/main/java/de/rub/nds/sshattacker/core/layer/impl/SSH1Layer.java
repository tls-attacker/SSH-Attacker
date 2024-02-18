/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.sshattacker.core.exceptions.TimeoutException;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerProcessingResult;
import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStreamAdapterStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.message.AsciiMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.AsciiMessageParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSH1Layer extends ProtocolLayer<ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public SSH1Layer(SshContext context) {
        super(ImplementedLayers.SSHV1);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        MessageIdConstant runningProtocolMessageType = null;
        ByteArrayOutputStream collectedMessageStream = new ByteArrayOutputStream();
        if (configuration != null) {
            LOGGER.debug(
                    "[bro] Sending following configuration-size {} with layer_0 is {}",
                    configuration.getContainerList().size(),
                    configuration.getContainerList().get(0).toCompactString());
        } else {
            LOGGER.debug("[bro] Configuration is null");
        }

        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : configuration.getContainerList()) {
                collectedMessageStream = new ByteArrayOutputStream();

                LOGGER.debug("[bro] here i am with sending the message");

                runningProtocolMessageType = message.getMessageIdConstant();
                processMessage(message, collectedMessageStream);
                addProducedContainer(message);
                flushCollectedMessages(runningProtocolMessageType, collectedMessageStream);

                ProtocolMessageHandler<?> handler = message.getHandler(context);
                if (handler instanceof MessageSentHandler) {
                    ((MessageSentHandler) handler).adjustContextAfterMessageSent();
                }
            }
        }

        if (runningProtocolMessageType == null) {
            LOGGER.debug("[bro] Protocol Message Type is null!");
        } else {
            LOGGER.debug("ProtocolMessageType: {}", runningProtocolMessageType.getId());
        }

        LOGGER.debug("[bro] " + "flushing {} to lower layer", collectedMessageStream.toByteArray());

        return getLayerResult();
    }

    private void processMessage(
            ProtocolMessage message, ByteArrayOutputStream collectedMessageStream)
            throws IOException {

        ProtocolMessagePreparator preparator = message.getPreparator(context);
        preparator.prepare();

        LOGGER.debug("Prepared packet");

        ProtocolMessageSerializer serializer = message.getSerializer(context);
        byte[] serializedMessage = serializer.serialize();
        message.setCompleteResultingMessage(serializedMessage);

        collectedMessageStream.writeBytes(message.getCompleteResultingMessage().getValue());

        /*   if (message.getCompleteResultingMessage().getValue()[0]
                        == ProtocolMessageType.SSH_MSG_NEWKEYS.getValue()
                || message.getCompleteResultingMessage().getValue()[0]
                        == ProtocolMessageType.SSH_MSG_KEXINIT.getValue()) {
            message.getHandler(context).adjustContextAfterMessageSent(message);
        } else {
            LOGGER.info(
                    "[bro] Adjusting Context while messagetype is {}",
                    message.getCompleteResultingMessage().getValue()[0]);
        }*/
    }

    private void flushCollectedMessages(
            MessageIdConstant runningProtocolMessageType, ByteArrayOutputStream byteStream)
            throws IOException {

        LOGGER.debug(
                "[bro] Sending the following {} on {}",
                byteStream.toByteArray(),
                getLowerLayer().getLayerType());
        if (byteStream.size() > 0) {
            getLowerLayer().sendData(byteStream.toByteArray());
            byteStream.reset();
        }
    }

    @Override
    public LayerProcessingResult sendData(byte[] additionalData) throws IOException {
        return sendConfiguration();
    }

    @Override
    public LayerProcessingResult receiveData() {
        LOGGER.debug("[bro] SSH-Layer ist Recieving Data now");

        try {
            HintedInputStream dataStream;
            do {
                try {
                    LOGGER.debug("[bro] I´m here");
                    dataStream = getLowerLayer().getDataStream();
                    LOGGER.debug("[bro] I was here");
                } catch (IOException e) {
                    // the lower layer does not give us any data so we can simply return here
                    LOGGER.debug("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                LOGGER.debug("[bro] Searching for Hint");

                byte[] streamContent;
                try {
                    LOGGER.debug("I could read {} bytes", dataStream.available());
                    streamContent = dataStream.readChunk(dataStream.available());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
                LOGGER.debug("STREAMCONTENT: {}", ArrayConverter.bytesToHexString(streamContent));

                AbstractPacket<?> packet;

                LOGGER.debug("[bro] Recieving a {}", context.getPacketLayer());
                if (context.getPacketLayerType() == PacketLayerType.BINARY_PACKET) {
                    packet = new BinaryPacket();
                } else if (context.getPacketLayerType() == PacketLayerType.BLOB) {
                    packet = new BlobPacket();
                } else {
                    throw new RuntimeException();
                }

                packet.setPayload(streamContent);

                parseMessageFromID(packet, context);
                /*
                if (tempHint == null) {
                    LOGGER.warn(
                            "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                } else if (tempHint instanceof PacketLayerHintSSHV1) {
                    PacketLayerHintSSHV1 hint = (PacketLayerHintSSHV1) dataStream.getHint();
                    LOGGER.debug("[bro] reading message for  Hint {}", hint.getType());
                    readMessageForHint(hint);
                }*/
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        }
        return getLayerResult();
    }

    public void parseMessageFromID(AbstractPacket<?> packet, SshContext context) {
        byte[] raw = packet.getPayload().getValue();
        if (packet instanceof BlobPacket) {
            String rawText = new String(packet.getPayload().getValue(), StandardCharsets.US_ASCII);
            if (rawText.startsWith("SSH-")) {
                readVersionExchangeProtocolData((BlobPacket) packet);
                return;
            } else {
                final AsciiMessage message = new AsciiMessage();
                AsciiMessageParser parser = new AsciiMessageParser(new ByteArrayInputStream(raw));
                parser.parse(message);

                // If we know what the text message means we can print a
                // human-readable warning to the log. The following
                // messages are sent by OpenSSH.
                final String messageText = message.getText().getValue();
                if ("Invalid SSH identification string.".equals(messageText)) {
                    LOGGER.warn(
                            "The server reported the identification string sent by the SSH-Attacker is invalid");
                } else if ("Exceeded MaxStartups".equals(messageText)) {
                    LOGGER.warn(
                            "The server reported the maximum number of concurrent unauthenticated connections has been exceeded.");
                }
                readASCIIData((BlobPacket) packet);
                return;
            }
        }

        MessageIdConstantSSH1 id =
                MessageIdConstantSSH1.fromId(
                        packet.getPayload().getValue()[0], context.getContext());

        LOGGER.debug("[bro] Identifier: {} and constant {}", packet.getPayload().getValue()[0], id);

        switch (id) {
            case SSH_MSG_DISCONNECT:
                LOGGER.debug("[bro] returning SSH_MSG_DISCONNECT Hint");
                readDisconnectData((BinaryPacket) packet);
                break;
            case SSH_CMSG_USER:
                LOGGER.debug("[bro] returning SSH_CMSG_USER Hint");
                readUserData((BinaryPacket) packet);
                break;
            case SSH_SMSG_PUBLIC_KEY:
                LOGGER.debug("[bro] returning SSH_SMSG_PUBLIC_KEY Hint");
                readPublicKeyData((BinaryPacket) packet);
                break;
            case SSH_CMSG_SESSION_KEY:
                LOGGER.debug("[bro] returning SSH_SMSG_PUBLIC_KEY Hint");
                readSessionKeyData((BinaryPacket) packet);
                break;
                // return new PacketLayerHintSSHV1(ProtocolMessageTypeSSHV1.SSH_SMSG_PUBLIC_KEY);
            case SSH_MSG_IGNORE:
                LOGGER.debug("[bro] returning SSH_MSG_IGNORE Hint");
                break;
                // return new PacketLayerHint(ProtocolMessageType.SSH_MSG_IGNORE);
            case SSH_MSG_DEBUG:
                LOGGER.debug("[bro] returning SSH_MSG_DEBUG Hint");
                break;
                // return new PacketLayerHint(ProtocolMessageType.SSH_MSG_DEBUG);
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_OPEN_CONFIRMATION Hint");
                break;
                /*return new PacketLayerHint(
                ProtocolMessageType.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);*/
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_OPEN_FAILURE Hint");
                break;
                // return new PacketLayerHint(ProtocolMessageType.SSH_MSG_CHANNEL_OPEN_FAILURE);
            case SSH_MSG_CHANNEL_DATA:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_DATA Hint");
                break;
                // return new PacketLayerHint(ProtocolMessageType.SSH_MSG_CHANNEL_DATA);
            case SSH_MSG_CHANNEL_CLOSE:
                LOGGER.debug("[bro] returning SSH_MSG_CHANNEL_CLOSE Hint");
                break;
                // return new PacketLayerHint(ProtocolMessageType.SSH_MSG_CHANNEL_CLOSE);
            case SSH_CMSG_AUTH_TIS:
                LOGGER.debug("[bro] returning SSH_CMSG_AUTH_TIS Hint");
                readSuccessMessage((BinaryPacket) packet);
                break;
            case SSH_SMSG_SUCCESS:
                LOGGER.debug("[bro] returning SSH_SMSG_SUCCESS Hint");
                readSuccessMessage((BinaryPacket) packet);
                break;
            case SSH_SMSG_FAILURE:
                LOGGER.debug("[bro] returning SSH_SMSG_FAILURE Hint");
                readFailureMessage((BinaryPacket) packet);
                break;
            default:
                LOGGER.debug(
                        "[bro] cannot identifie {} as {} - returningn null",
                        raw[1],
                        MessageIdConstant.fromId(
                                packet.getPayload().getValue()[0], context.getContext()));
                // return null;
        }
    }

    private void readUnknownProtocolData() {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
    }

    private void readSessionKeyData(AbstractPacket<BinaryPacket> packet) {
        ClientSessionKeyMessage message = new ClientSessionKeyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readDisconnectData(AbstractPacket<BinaryPacket> packet) {
        DisconnectMessageSSH1 message = new DisconnectMessageSSH1();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserData(AbstractPacket<BinaryPacket> packet) {
        UserMessageSSH1 message = new UserMessageSSH1();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readSuccessMessage(AbstractPacket<BinaryPacket> packet) {
        SuccessMessageSSH1 message = new SuccessMessageSSH1();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readFailureMessage(AbstractPacket<BinaryPacket> packet) {
        FailureMessageSSH1 message = new FailureMessageSSH1();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readPublicKeyData(AbstractPacket<BinaryPacket> packet) {
        ServerPublicKeyMessage message = new ServerPublicKeyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
        // readDataContainer(message, context);
    }

    private void readASCIIData(AbstractPacket<BlobPacket> packet) {
        AsciiMessage message = new AsciiMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
        // readDataContainer(message, context);
    }

    private void readVersionExchangeProtocolData(AbstractPacket<BlobPacket> packet) {
        VersionExchangeMessageSSHV1 message = new VersionExchangeMessageSSHV1();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);

        // readDataContainer(message, context);
    }

    /*private static int resolvePaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_TWO_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }

    private static int resolveUnpaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_ONE_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }*/

    @Override
    public void receiveMoreData() throws IOException {
        try {
            HintedInputStream dataStream = null;
            dataStream = getLowerLayer().getDataStream();
            currentInputStream = new HintedLayerInputStream(this);
            currentInputStream.extendStream(dataStream.readAllBytes());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
            throw ex;
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more dtls fragments", ex);
            throw ex;
        }
    }
}
