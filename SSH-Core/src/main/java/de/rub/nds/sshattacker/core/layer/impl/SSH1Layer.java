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
                readDataFromStream(new VersionExchangeMessageSSHV1(), (BlobPacket) packet);
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
                readDataFromStream(new AsciiMessage(), (BlobPacket) packet);
                return;
            }
        }

        MessageIdConstantSSH1 id =
                MessageIdConstantSSH1.fromId(
                        packet.getPayload().getValue()[0], context.getContext());

        LOGGER.debug("[bro] Identifier: {} and constant {}", packet.getPayload().getValue()[0], id);

        switch (id) {
            case SSH_MSG_DISCONNECT:
                LOGGER.debug("[bro] Reading SSH_MSG_DISCONNECT Paket");
                readDataFromStream(new DisconnectMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_USER:
                LOGGER.debug("[bro] Reading SSH_CMSG_USER Paket");
                readDataFromStream(new UserMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_PUBLIC_KEY:
                LOGGER.debug("[bro] Reading SSH_SMSG_PUBLIC_KEY Paket");
                readDataFromStream(new ServerPublicKeyMessage(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_SESSION_KEY:
                LOGGER.debug("[bro] Reading SSH_CMSG_SESSION_KEY Paket");
                readDataFromStream(new ClientSessionKeyMessage(), (BinaryPacket) packet);
                break;
            case SSH_MSG_IGNORE:
                LOGGER.debug("[bro] Reading SSH_MSG_IGNORE Paket");
                readDataFromStream(new IgnoreMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_DEBUG:
                LOGGER.debug("[bro] Reading SSH_MSG_DEBUG Paket");
                readDataFromStream(new DebugMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EOF:
                LOGGER.debug("[bro] Reading SSH_CMSG_EOF Paket");
                readDataFromStream(new EofMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXEC_CMD:
                LOGGER.debug("[bro] Reading SSH_CMSG_EXEC_CMD Paket");
                readDataFromStream(new ExecCmdMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXEC_SHELL:
                LOGGER.debug("[bro] Reading SSH_CMSG_EXEC_SHELL Paket");
                readDataFromStream(new ExecShellMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXIT_CONFIRMATION:
                LOGGER.debug("[bro] Reading SSH_CMSG_EXIT_CONFIRMATION Paket");
                readDataFromStream(new ExitConfirmationMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_STDIN_DATA:
                LOGGER.debug("[bro] Reading SSH_CMSG_STDIN_DATA Paket");
                readDataFromStream(new StdinDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_STDOUT_DATA:
                LOGGER.debug("[bro] Reading SSH_SMSG_STDOUT_DATA Paket");
                readDataFromStream(new StdoutDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_STDERR_DATA:
                LOGGER.debug("[bro] Reading SSH_SMSG_STDERR_DATA Paket");
                readDataFromStream(new StderrDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                LOGGER.debug("[bro] Reading SSH_MSG_CHANNEL_OPEN_CONFIRMATION Paket");
                break;
            case SSH_SMSG_EXITSTATUS:
                LOGGER.debug("[bro] Reading SSH_SMSG_EXITSTATUS Paket");
                readDataFromStream(new ExitStatusMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                LOGGER.debug("[bro] Reading SSH_MSG_CHANNEL_OPEN_FAILURE Paket");
                break;
            case SSH_MSG_CHANNEL_DATA:
                LOGGER.debug("[bro] Reading SSH_MSG_CHANNEL_DATA Paket");
                break;
            case SSH_MSG_CHANNEL_CLOSE:
                LOGGER.debug("[bro] Reading SSH_MSG_CHANNEL_CLOSE Paket");
                break;
            case SSH_CMSG_AUTH_TIS:
                LOGGER.debug("[bro] Reading SSH_CMSG_AUTH_TIS Paket");
                break;
            case SSH_SMSG_SUCCESS:
                LOGGER.debug("[bro] Reading SSH_SMSG_SUCCESS Paket");
                readDataFromStream(new SuccessMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_FAILURE:
                LOGGER.debug("[bro] Reading SSH_SMSG_FAILURE Paket");
                readDataFromStream(new FailureMessageSSH1(), (BinaryPacket) packet);
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

    private void readDataFromStream(ProtocolMessage<?> message, AbstractPacket<?> packet) {
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

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
