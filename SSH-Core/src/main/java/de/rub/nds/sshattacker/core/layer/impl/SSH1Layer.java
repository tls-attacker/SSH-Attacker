/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

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
import de.rub.nds.sshattacker.core.layer.stream.LayerInputStream;
import de.rub.nds.sshattacker.core.layer.stream.LayerInputStreamAdapterStream;
import de.rub.nds.sshattacker.core.layer.stream.LayerLayerInputStream;
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

        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : configuration.getContainerList()) {
                collectedMessageStream = new ByteArrayOutputStream();
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
    }

    private void flushCollectedMessages(
            MessageIdConstant runningProtocolMessageType, ByteArrayOutputStream byteStream)
            throws IOException {
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

        try {
            LayerInputStream dataStream;
            do {
                try {
                    dataStream = getLowerLayer().getDataStream();
                } catch (IOException e) {
                    // the lower layer does not give us any data so we can simply return here
                    LOGGER.debug("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                byte[] streamContent;
                try {
                    LOGGER.debug("The Stream holds {} bytes", dataStream.available());
                    streamContent = dataStream.readChunk(dataStream.available());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                AbstractPacket<?> packet;

                if (context.getPacketLayerType() == PacketLayerType.BINARY_PACKET) {
                    packet = new BinaryPacket();
                } else if (context.getPacketLayerType() == PacketLayerType.BLOB) {
                    packet = new BlobPacket();
                } else {
                    throw new RuntimeException();
                }

                packet.setPayload(streamContent);
                parseMessageFromID(packet, context);

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
                readDataFromStream(new DisconnectMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_USER:
                readDataFromStream(new UserMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_PUBLIC_KEY:
                readDataFromStream(new ServerPublicKeyMessage(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_SESSION_KEY:
                readDataFromStream(new ClientSessionKeyMessage(), (BinaryPacket) packet);
                break;
            case SSH_MSG_IGNORE:
                readDataFromStream(new IgnoreMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_DEBUG:
                readDataFromStream(new DebugMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EOF:
                readDataFromStream(new EofMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXEC_CMD:
                readDataFromStream(new ExecCmdMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXEC_SHELL:
                readDataFromStream(new ExecShellMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_EXIT_CONFIRMATION:
                readDataFromStream(new ExitConfirmationMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_STDIN_DATA:
                readDataFromStream(new StdinDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_STDOUT_DATA:
                readDataFromStream(new StdoutDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_STDERR_DATA:
                readDataFromStream(new StderrDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                readDataFromStream(new ChannelOpenConfirmationMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_EXITSTATUS:
                readDataFromStream(new ExitStatusMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                readDataFromStream(new ChannelOpenFailureMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_DATA:
                readDataFromStream(new ChannelDataMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_CLOSE:
                readDataFromStream(new ChannelCloseMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_CHANNEL_CLOSE_CONFIRMATION:
                readDataFromStream(
                        new ChannelCloseConfirmationMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AUTH_RSA:
                readDataFromStream(new RsaAuthMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_PORT_FORWARD_REQUEST:
                readDataFromStream(new PortForwardRequestMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AGENT_REQUEST_FORWARDING:
                readDataFromStream(new AgentRequestForwardingMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AUTH_PASSWORD:
                readDataFromStream(new AuthPasswordSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AUTH_RHOSTS:
                readDataFromStream(new AuthRhostsSSH1(), (BinaryPacket) packet);
                break;
            case SSH_MSG_PORT_OPEN:
                readDataFromStream(new PortOpenMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_AGENT_OPEN:
                readDataFromStream(new AgentOpenMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_X11_OPEN:
                readDataFromStream(new X11OpenMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_SUCCESS:
                readDataFromStream(new SuccessMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_SMSG_FAILURE:
                readDataFromStream(new FailureMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AUTH_RSA_RESPONSE:
                readDataFromStream(new AuthRsaResponseMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_REQUEST_PTY:
                readDataFromStream(new RequestPtyMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_WINDOW_SIZE:
                readDataFromStream(new WindowSizeMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_AUTH_RHOSTS_RSA:
                readDataFromStream(new AuthRhostsRsaMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_REQUEST_COMPRESSION:
                readDataFromStream(new RequestCompressionMessageSSH1(), (BinaryPacket) packet);
                break;
            case SSH_CMSG_X11_REQUEST_FORWARDING:
                readDataFromStream(new X11RequestForwardMessageSSH1(), (BinaryPacket) packet);
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
        LayerInputStream temp_stream;

        temp_stream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    @Override
    public void receiveMoreData() throws IOException {
        try {
            LayerInputStream dataStream = null;
            dataStream = getLowerLayer().getDataStream();
            currentInputStream = new LayerLayerInputStream(this);
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
