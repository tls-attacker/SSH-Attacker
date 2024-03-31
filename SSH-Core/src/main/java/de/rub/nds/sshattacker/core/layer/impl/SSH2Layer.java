/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

import de.rub.nds.sshattacker.core.constants.*;
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
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.*;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import de.rub.nds.sshattacker.core.protocol.transport.parser.AsciiMessageParser;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSH2Layer extends ProtocolLayer<ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public SSH2Layer(SshContext context) {
        super(ImplementedLayers.SSHV2);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        ByteArrayOutputStream collectedMessageStream = new ByteArrayOutputStream();

        if (configuration != null && configuration.getContainerList() != null) {
            for (ProtocolMessage message : configuration.getContainerList()) {
                collectedMessageStream = new ByteArrayOutputStream();
                processMessage(message, collectedMessageStream);
                addProducedContainer(message);
                flushCollectedMessages(collectedMessageStream);

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

    private void flushCollectedMessages(ByteArrayOutputStream byteStream) throws IOException {
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
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }

                byte[] streamContent;
                try {
                    // LOGGER.debug("I could read {} bytes", dataStream.available());
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

        MessageIdConstant id =
                MessageIdConstant.fromId(packet.getPayload().getValue()[0], context.getContext());

        switch (MessageIdConstant.fromId(packet.getPayload().getValue()[0], context.getContext())) {
            case SSH_MSG_DISCONNECT:
                readMessageFromStream(new DisconnectMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_IGNORE:
                readMessageFromStream(new IgnoreMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_UNIMPLEMENTED:
                return;
            case SSH_MSG_DEBUG:
                return;
            case SSH_MSG_SERVICE_ACCEPT:
                readMessageFromStream(new ServiceAcceptMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_EXT_INFO:
                return;
            case SSH_MSG_NEWCOMPRESS:
                return;
            case SSH_MSG_KEXINIT:
                readMessageFromStream(new KeyExchangeInitMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_NEWKEYS:
                readMessageFromStream(new NewKeysMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
                readMessageFromStream(
                        new DhGexKeyExchangeOldRequestMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REQUEST:
                readMessageFromStream(new DhGexKeyExchangeRequestMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_GROUP:
                readMessageFromStream(new DhGexKeyExchangeGroupMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_INIT:
                readMessageFromStream(new DhGexKeyExchangeInitMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REPLY:
                readMessageFromStream(new DhGexKeyExchangeReplyMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEXDH_INIT:
                readMessageFromStream(new DhKeyExchangeInitMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEXDH_REPLY:
                readMessageFromStream(new DhKeyExchangeReplyMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_HBR_INIT:
                readMessageFromStream(new HybridKeyExchangeInitMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_HBR_REPLY:
                readMessageFromStream(new HybridKeyExchangeReplyMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_SERVICE_REQUEST:
                readMessageFromStream(new ServiceRequestMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_ECDH_INIT:
                readMessageFromStream(new EcdhKeyExchangeInitMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_ECDH_REPLY:
                readMessageFromStream(new EcdhKeyExchangeReplyMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_ECMQV_INIT:
                return;
            case SSH_MSG_ECMQV_REPLY:
                return;
            case SSH_MSG_KEXRSA_PUBKEY:
                readMessageFromStream(new RsaKeyExchangePubkeyMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEXRSA_SECRET:
                readMessageFromStream(new RsaKeyExchangeSecretMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEXRSA_DONE:
                readMessageFromStream(new RsaKeyExchangeDoneMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_KEXGSS_INIT:
                return;
            case SSH_MSG_KEXGSS_CONTINUE:
                return;
            case SSH_MSG_KEXGSS_COMPLETE:
                return;
            case SSH_MSG_KEXGSS_HOSTKEY:
                return;
            case SSH_MSG_KEXGSS_ERROR:
                return;
            case SSH_MSG_KEXGSS_GROUPREQ:
                return;
            case SSH_MSG_KEXGSS_GROUP:
                return;
            case SSH_MSG_USERAUTH_REQUEST:
                readUserAuthReq((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_FAILURE:
                readMessageFromStream(new UserAuthFailureMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_SUCCESS:
                readMessageFromStream(new UserAuthSuccessMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_BANNER:
                readMessageFromStream(new UserAuthBannerMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_PK_OK:
                return;
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
                return;
            case SSH_MSG_USERAUTH_INFO_REQUEST:
                readMessageFromStream(new UserAuthInfoRequestMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_INFO_RESPONSE:
                readMessageFromStream(new UserAuthInfoResponseMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_GSSAPI_RESPONSE:
                return;
            case SSH_MSG_USERAUTH_GSSAPI_TOKEN:
                return;
            case SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE:
                return;
            case SSH_MSG_USERAUTH_GSSAPI_ERROR:
                return;
            case SSH_MSG_USERAUTH_GSSAPI_ERRTOK:
                return;
            case SSH_MSG_USERAUTH_GSSAPI_MIC:
                return;
            case SSH_MSG_GLOBAL_REQUEST:
                readGlobalRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_REQUEST_SUCCESS:
                readMessageFromStream(new GlobalRequestSuccessMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_REQUEST_FAILURE:
                readMessageFromStream(new GlobalRequestFailureMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN:
                readChannelOpen((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                readMessageFromStream(new ChannelOpenConfirmationMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                readMessageFromStream(new ChannelOpenFailureMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                readMessageFromStream(new ChannelWindowAdjustMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_DATA:
                readMessageFromStream(new ChannelDataMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                readMessageFromStream(new ChannelExtendedDataMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_EOF:
                readMessageFromStream(new ChannelEofMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_CLOSE:
                readMessageFromStream(new ChannelCloseMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_REQUEST:
                readChannelRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_SUCCESS:
                readMessageFromStream(new ChannelSuccessMessage(), (BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_FAILURE:
                readMessageFromStream(new ChannelFailureMessage(), (BinaryPacket) packet);
                return;
            case UNKNOWN:
                return;
            default:
                LOGGER.debug(
                        "[bro] cannot identifie {} as {} - parsingn null",
                        raw[1],
                        MessageIdConstant.fromId(
                                packet.getPayload().getValue()[0], context.getContext()));
        }
    }

    private void readUserAuthReq(AbstractPacket<BinaryPacket> packet) {
        UserAuthUnknownMessage userAuthUnknownMessage = new UserAuthUnknownMessage();
        LayerInputStream inputStream;
        LayerInputStream temp_stream;
        inputStream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        UserAuthUnknownMessageParser parser = new UserAuthUnknownMessageParser(inputStream);
        parser.parse(userAuthUnknownMessage);
        String methodString = userAuthUnknownMessage.getMethodName().getValue();
        try {
            LOGGER.info(
                    "Got Method-Request: {}, remainign in Inpustream: {}",
                    methodString,
                    inputStream.available());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        AuthenticationMethod method = AuthenticationMethod.fromName(methodString);
        switch (method) {
            case NONE:
                LOGGER.info("Parsing Authenticationmethod: None");
                UserAuthNoneMessage userAuthNoneMessage = new UserAuthNoneMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        userAuthUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(userAuthNoneMessage, context, temp_stream);

                break;
            case PASSWORD:
                LOGGER.info("Parsing Authenticationmethod: Password");
                UserAuthPasswordMessage userAuthPasswordMessage = new UserAuthPasswordMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        userAuthUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));

                readContainerFromStream(userAuthPasswordMessage, context, temp_stream);

                break;
            case PUBLICKEY:
                LOGGER.info("Parsing Authenticationmethod: PubKey");
                UserAuthPubkeyMessage userAuthPubkeyMessage = new UserAuthPubkeyMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        userAuthUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(userAuthPubkeyMessage, context, temp_stream);

                break;
            case HOST_BASED:
                LOGGER.info("Parsing Authenticationmethod: Hostbased");
                UserAuthHostbasedMessage userAuthHostbasedMessage = new UserAuthHostbasedMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        userAuthUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(userAuthHostbasedMessage, context, temp_stream);

            case KEYBOARD_INTERACTIVE:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                UserAuthKeyboardInteractiveMessage userAuthKeyboardInteractiveMessage =
                        new UserAuthKeyboardInteractiveMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        userAuthUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(userAuthKeyboardInteractiveMessage, context, temp_stream);

            default:
                LOGGER.debug(
                        "Received unimplemented user authentication method in user authentication request: {}",
                        methodString);
                break;
        }

        LOGGER.info("Done with Parsing UserAuth");
    }

    private void readChannelRequest(AbstractPacket<BinaryPacket> packet) {
        ChannelRequestUnknownMessage channelRequestUnknownMessage =
                new ChannelRequestUnknownMessage();
        LayerInputStream inputStream;
        LayerInputStream temp_stream;

        inputStream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));

        ChannelRequestUnknownMessageParser parser =
                new ChannelRequestUnknownMessageParser(inputStream);
        parser.parse(channelRequestUnknownMessage);
        String requestTypeString = channelRequestUnknownMessage.getRequestType().getValue();
        try {
            LOGGER.info(
                    "Got Method-Request: {}, remainign in Inpustream: {}",
                    requestTypeString,
                    inputStream.available());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        ChannelRequestType requestType = ChannelRequestType.fromName(requestTypeString);
        switch (requestType) {
            case PTY_REQ:
                LOGGER.info("Parsing Authenticationmethod: None");
                ChannelRequestPtyMessage channelRequestPtyMessage = new ChannelRequestPtyMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestPtyMessage, context, temp_stream);

                break;
            case X11_REQ:
                LOGGER.info("Parsing Authenticationmethod: Password");
                ChannelRequestX11Message channelRequestX11Message = new ChannelRequestX11Message();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));

                readContainerFromStream(channelRequestX11Message, context, temp_stream);

                break;
            case ENV:
                LOGGER.info("Parsing Authenticationmethod: PubKey");
                ChannelRequestEnvMessage channelRequestEnvMessage = new ChannelRequestEnvMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestEnvMessage, context, temp_stream);

                break;
            case SHELL:
                LOGGER.info("Parsing Authenticationmethod: Hostbased");
                ChannelRequestShellMessage channelRequestShellMessage =
                        new ChannelRequestShellMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestShellMessage, context, temp_stream);

            case EXEC:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestExecMessage channelRequestExecMessage =
                        new ChannelRequestExecMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestExecMessage, context, temp_stream);

            case SUBSYSTEM:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestSubsystemMessage channelRequestSubsystemMessage =
                        new ChannelRequestSubsystemMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestSubsystemMessage, context, temp_stream);

            case WINDOW_CHANGE:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestWindowChangeMessage channelRequestWindowChangeMessage =
                        new ChannelRequestWindowChangeMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestWindowChangeMessage, context, temp_stream);
            case XON_XOFF:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestXonXoffMessage channelRequestXonXoffMessage =
                        new ChannelRequestXonXoffMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestXonXoffMessage, context, temp_stream);
            case SIGNAL:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestSignalMessage channelRequestSignalMessage =
                        new ChannelRequestSignalMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestSignalMessage, context, temp_stream);
            case EXIT_STATUS:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestExitStatusMessage channelRequestExitStatusMessage =
                        new ChannelRequestExitStatusMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestExitStatusMessage, context, temp_stream);
            case EXIT_SIGNAL:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestExitSignalMessage channelRequestExitSignalMessage =
                        new ChannelRequestExitSignalMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestExitSignalMessage, context, temp_stream);
            case AUTH_AGENT_REQ_OPENSSH_COM:
                LOGGER.info("Parsing Authenticationmethod: Interactive");
                ChannelRequestAuthAgentMessage channelRequestAuthAgentMessage =
                        new ChannelRequestAuthAgentMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelRequestAuthAgentMessage, context, temp_stream);
            default:
                LOGGER.debug(
                        "Received unimplemented user authentication method in user authentication request: {}",
                        requestType);
                break;
        }

        LOGGER.info("Done with Parsing UserAuth");
    }

    private void readGlobalRequest(AbstractPacket<BinaryPacket> packet) {
        GlobalRequestUnknownMessage globalRequestUnknownMessage = new GlobalRequestUnknownMessage();
        LayerInputStream inputStream;
        LayerInputStream temp_stream;

        inputStream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));

        GlobalRequestUnknownMessageParser parser =
                new GlobalRequestUnknownMessageParser(inputStream);
        parser.parse(globalRequestUnknownMessage);
        String requestTypeString = globalRequestUnknownMessage.getRequestName().getValue();
        GlobalRequestType requestType = GlobalRequestType.fromName(requestTypeString);
        switch (requestType) {
            case TCPIP_FORWARD:
                GlobalRequestTcpIpForwardMessage tcpIpForwardMessage =
                        new GlobalRequestTcpIpForwardMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(tcpIpForwardMessage, context, temp_stream);
            case CANCEL_TCPIP_FORWARD:
                GlobalRequestCancelTcpIpForwardMessage cancelTcpIpForwardMessage =
                        new GlobalRequestCancelTcpIpForwardMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(cancelTcpIpForwardMessage, context, temp_stream);
            case NO_MORE_SESSIONS_OPENSSH_COM:
                GlobalRequestNoMoreSessionsMessage noMoreSessionsMessage =
                        new GlobalRequestNoMoreSessionsMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(noMoreSessionsMessage, context, temp_stream);
            case HOSTKEYS_00_OPENSSH_COM:
                GlobalRequestOpenSshHostKeysMessage openSshHostKeysMessage =
                        new GlobalRequestOpenSshHostKeysMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(openSshHostKeysMessage, context, temp_stream);
            default:
                LOGGER.debug(
                        "Received unimplemented channel open message type: {}", requestTypeString);
        }
    }

    private void readASCIIData(AbstractPacket<BlobPacket> packet) {
        AsciiMessage message = new AsciiMessage();
        LayerInputStream temp_stream;

        temp_stream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readMessageFromStream(ProtocolMessage<?> message, AbstractPacket<?> packet) {
        LayerInputStream temp_stream;

        temp_stream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelOpen(AbstractPacket<BinaryPacket> packet) {
        ChannelOpenUnknownMessage channelOpenUnknownMessage = new ChannelOpenUnknownMessage();
        LayerInputStream inputStream;
        LayerInputStream temp_stream;
        inputStream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));

        ChannelOpenUnknownMessageParser parser = new ChannelOpenUnknownMessageParser(inputStream);
        parser.parse(channelOpenUnknownMessage);
        String channelTypeString = channelOpenUnknownMessage.getChannelType().getValue();
        ChannelType channelType = ChannelType.fromName(channelTypeString);
        switch (channelType) {
            case SESSION:
                ChannelOpenSessionMessage channelOpenSessionMessage =
                        new ChannelOpenSessionMessage();
                temp_stream =
                        new LayerInputStreamAdapterStream(
                                new ByteArrayInputStream(
                                        channelOpenUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(channelOpenSessionMessage, context, temp_stream);
            default:
                LOGGER.debug(
                        "Received unimplemented channel open message type: {}", channelTypeString);
        }
    }

    private void readVersionExchangeProtocolData(AbstractPacket<BlobPacket> packet) {
        VersionExchangeMessage message = new VersionExchangeMessage();

        LayerInputStream temp_stream;

        temp_stream =
                new LayerInputStreamAdapterStream(
                        new ByteArrayInputStream(packet.getPayload().getValue()));

        readContainerFromStream(message, context, temp_stream);
    }

    /**
     * Parses the handshake layer header from the given message and parses the encapsulated message
     * using the correct parser.
     *
     * @throws IOException
     */
    private void readUnknownProtocolData() {
        UnknownMessage message = new UnknownMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
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
