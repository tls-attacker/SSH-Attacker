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
import de.rub.nds.sshattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.sshattacker.core.layer.hints.PacketLayerHint;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStreamAdapterStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedLayerInputStream;
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

public class SSH2Layer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public SSH2Layer(SshContext context) {
        super(ImplementedLayers.SSHV2);
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
                // flushCollectedMessages(runningProtocolMessageType, collectedMessageStream);
                getLowerLayer().sendData(collectedMessageStream.toByteArray());

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
                    LOGGER.warn("The lower layer did not produce a data stream: ", e);
                    return getLayerResult();
                }
                LOGGER.debug("[bro] Searching for Message");
                LayerProcessingHint tempHint = dataStream.getHint();

                byte[] streamContent;
                try {
                    LOGGER.debug("I could read {} bytes", dataStream.available());
                    streamContent = dataStream.readChunk(dataStream.available());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

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
        LOGGER.debug("[bro] Identifier: {} and constant {}", packet.getPayload().getValue()[0], id);

        switch (MessageIdConstant.fromId(packet.getPayload().getValue()[0], context.getContext())) {
            case SSH_MSG_DISCONNECT:
                LOGGER.debug("[bro] parsing SSH_MSG_DISCONNECT Message");
                readDisconnect((BinaryPacket) packet);
                return;
            case SSH_MSG_IGNORE:
                LOGGER.debug("[bro] parsing SSH_MSG_IGNORE Message");
                readIngoreMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_UNIMPLEMENTED:
                LOGGER.debug("[bro] parsing SSH_MSG_UNIMPLEMENTED Message");
                return;
            case SSH_MSG_DEBUG:
                LOGGER.debug("[bro] parsing SSH_MSG_DEBUG Message");
                return;
            case SSH_MSG_SERVICE_ACCEPT:
                LOGGER.debug("[bro] parsing SSH_MSG_SERVICE_ACCEPT Message");
                readMsgServiceAccept((BinaryPacket) packet);
                return;
            case SSH_MSG_EXT_INFO:
                LOGGER.debug("[bro] parsing SSH_MSG_EXT_INFO Message");
                return;
            case SSH_MSG_NEWCOMPRESS:
                LOGGER.debug("[bro] parsing SSH_MSG_NEWCOMPRESS Message");
                return;
            case SSH_MSG_KEXINIT:
                LOGGER.debug("[bro] parsing SSH KEX INIT Message");
                readKexInitProtocolData((BinaryPacket) packet);
                return;
            case SSH_MSG_NEWKEYS:
                LOGGER.debug("[bro] parsing SSH_MSG_NEWKEYS Message");
                readNewKeysProtocolData((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REQUEST_OLD:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_DH_GEX_REQUEST_OLD Message");
                readGexDHExchangeOldRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_DH_GEX_REQUEST Message");
                readGexDHExchangeRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_GROUP:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_DH_GEX_GROUP Message");
                readGexKeyExchangeGroup((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_DH_GEX_INIT Message");
                readGexDHExchangeInitMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_DH_GEX_REPLY:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_DH_GEX_REPLY Message");
                readGexDHExchangeReplyMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_KEXDH_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXDH_INIT Message");
                readDhKeyInitMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_KEXDH_REPLY:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXDH_REPLY Message");
                readDhKeyReplyMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_HBR_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_HBR_INIT Message");
                readHbrInitProtocolData((BinaryPacket) packet);
                return;
            case SSH_MSG_HBR_REPLY:
                LOGGER.debug("[bro] parsing SSH_MSG_HBR_REPLY Message");
                readHbrReplProtocolData((BinaryPacket) packet);
                return;
            case SSH_MSG_SERVICE_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_SERVICE_REQUEST Message");
                readServiceRequestData((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_ECDH_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_ECDH_INIT Message");
                readKexECDHInit((BinaryPacket) packet);
                return;
            case SSH_MSG_KEX_ECDH_REPLY:
                LOGGER.debug("[bro] parsing SSH_MSG_KEX_ECDH_REPLY Message");
                readKexECDHReply((BinaryPacket) packet);
                return;
            case SSH_MSG_ECMQV_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_ECMQV_INIT Message");
                return;
            case SSH_MSG_ECMQV_REPLY:
                LOGGER.debug("[bro] parsing SSH_MSG_ECMQV_REPLY Message");
                return;
            case SSH_MSG_KEXRSA_PUBKEY:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXRSA_PUBKEY Message");
                readKeyExchangeRSAPubkeyMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_KEXRSA_SECRET:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXRSA_SECRET Message");
                readKeyExchangeRSASecret((BinaryPacket) packet);
                return;
            case SSH_MSG_KEXRSA_DONE:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXRSA_DONE Message");
                readKeyExchangeRSADone((BinaryPacket) packet);
                return;
            case SSH_MSG_KEXGSS_INIT:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_INIT Message");
                return;
            case SSH_MSG_KEXGSS_CONTINUE:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_CONTINUE Message");
                return;
            case SSH_MSG_KEXGSS_COMPLETE:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_COMPLETE Message");
                return;
            case SSH_MSG_KEXGSS_HOSTKEY:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_HOSTKEY Message");
                return;
            case SSH_MSG_KEXGSS_ERROR:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_ERROR Message");
                return;
            case SSH_MSG_KEXGSS_GROUPREQ:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_GROUPREQ Message");
                return;
            case SSH_MSG_KEXGSS_GROUP:
                LOGGER.debug("[bro] parsing SSH_MSG_KEXGSS_GROUP Message");
                return;
            case SSH_MSG_USERAUTH_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_REQUEST Message");
                readUserAuthReq((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_FAILURE:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_FAILURE Message");
                readUserAuthFail((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_SUCCESS:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_SUCCESS Message");
                readUserAuthSucc((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_BANNER:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_BANNER Message");
                readUserAuthBanner((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_PK_OK:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_PK_OK Message");
                return;
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_PASSWD_CHANGEREQ Message");
                return;
            case SSH_MSG_USERAUTH_INFO_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_INFO_REQUEST Message");
                readUserAuthInfoReq((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_INFO_RESPONSE:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_INFO_RESPONSE Message");
                readUserAuthInfoResp((BinaryPacket) packet);
                return;
            case SSH_MSG_USERAUTH_GSSAPI_RESPONSE:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_RESPONSE Message");
                return;
            case SSH_MSG_USERAUTH_GSSAPI_TOKEN:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_TOKEN Message");
                return;
            case SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE Message");
                return;
            case SSH_MSG_USERAUTH_GSSAPI_ERROR:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_ERROR Message");
                return;
            case SSH_MSG_USERAUTH_GSSAPI_ERRTOK:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_ERRTOK Message");
                return;
            case SSH_MSG_USERAUTH_GSSAPI_MIC:
                LOGGER.debug("[bro] parsing SSH_MSG_USERAUTH_GSSAPI_MIC Message");
                return;
            case SSH_MSG_GLOBAL_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_GLOBAL_REQUEST Message");
                readGlobalRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_REQUEST_SUCCESS:
                LOGGER.debug("[bro] parsing SSH_MSG_REQUEST_SUCCESS Message");
                readRequestSuccess((BinaryPacket) packet);
                return;
            case SSH_MSG_REQUEST_FAILURE:
                LOGGER.debug("[bro] parsing SSH_MSG_REQUEST_FAILURE Message");
                readRequestFailure((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_OPEN Message");
                readChannelOpen((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_OPEN_CONFIRMATION Message");
                readChannelOpenConfirmation((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_OPEN_FAILURE Message");
                readChannelOpenFailureMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_WINDOW_ADJUST:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_WINDOW_ADJUST Message");
                readChannelWindowsAdjust((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_DATA:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_DATA Message");
                readChannelDataMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_EXTENDED_DATA Message");
                readChannelExtendedDataMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_EOF:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_EOF Message");
                readChannelCloseMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_CLOSE:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_CLOSE Message");
                readChannelCloseMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_REQUEST:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_REQUEST Message");
                readChannelRequest((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_SUCCESS:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_SUCCESS Message");
                readChannelSuccessMessage((BinaryPacket) packet);
                return;
            case SSH_MSG_CHANNEL_FAILURE:
                LOGGER.debug("[bro] parsing SSH_MSG_CHANNEL_FAILURE Message");
                readChannelFailureMessage((BinaryPacket) packet);
                return;
            case UNKNOWN:
                LOGGER.debug("[bro] parsing UNKNOWN Message");
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
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        inputStream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
        HintedInputStream inputStream;
        HintedInputStream temp_stream;

        inputStream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));

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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
                        new HintedInputStreamAdapterStream(
                                null,
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
        HintedInputStream inputStream;
        HintedInputStream temp_stream;

        inputStream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));

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
                        new HintedInputStreamAdapterStream(
                                null,
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(tcpIpForwardMessage, context, temp_stream);
            case CANCEL_TCPIP_FORWARD:
                GlobalRequestCancelTcpIpForwardMessage cancelTcpIpForwardMessage =
                        new GlobalRequestCancelTcpIpForwardMessage();
                temp_stream =
                        new HintedInputStreamAdapterStream(
                                null,
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(cancelTcpIpForwardMessage, context, temp_stream);
            case NO_MORE_SESSIONS_OPENSSH_COM:
                GlobalRequestNoMoreSessionsMessage noMoreSessionsMessage =
                        new GlobalRequestNoMoreSessionsMessage();
                temp_stream =
                        new HintedInputStreamAdapterStream(
                                null,
                                new ByteArrayInputStream(
                                        globalRequestUnknownMessage
                                                .getCompleteResultingMessage()
                                                .getOriginalValue()));
                readContainerFromStream(noMoreSessionsMessage, context, temp_stream);
            case HOSTKEYS_00_OPENSSH_COM:
                GlobalRequestOpenSshHostKeysMessage openSshHostKeysMessage =
                        new GlobalRequestOpenSshHostKeysMessage();
                temp_stream =
                        new HintedInputStreamAdapterStream(
                                null,
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
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readIngoreMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelSuccessMessage message = new ChannelSuccessMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKexECDHInit(AbstractPacket<BinaryPacket> packet) {
        EcdhKeyExchangeInitMessage message = new EcdhKeyExchangeInitMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKexECDHReply(AbstractPacket<BinaryPacket> packet) {
        EcdhKeyExchangeReplyMessage message = new EcdhKeyExchangeReplyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelSuccessMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelSuccessMessage message = new ChannelSuccessMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelCloseMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelCloseMessage message = new ChannelCloseMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelEofMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelEofMessage message = new ChannelEofMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelExtendedDataMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelExtendedDataMessage message = new ChannelExtendedDataMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelFailureMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelFailureMessage message = new ChannelFailureMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelOpenFailureMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelOpenFailureMessage message = new ChannelOpenFailureMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelOpenConfirmation(AbstractPacket<BinaryPacket> packet) {
        ChannelOpenConfirmationMessage message = new ChannelOpenConfirmationMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserAuthSucc(AbstractPacket<BinaryPacket> packet) {
        UserAuthSuccessMessage message = new UserAuthSuccessMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readDisconnect(AbstractPacket<BinaryPacket> packet) {
        DisconnectMessage message = new DisconnectMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readGexDHExchangeOldRequest(AbstractPacket<BinaryPacket> packet) {
        DhGexKeyExchangeOldRequestMessage message = new DhGexKeyExchangeOldRequestMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readGexKeyExchangeGroup(AbstractPacket<BinaryPacket> packet) {
        DhGexKeyExchangeGroupMessage message = new DhGexKeyExchangeGroupMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readGexDHExchangeRequest(AbstractPacket<BinaryPacket> packet) {
        DhGexKeyExchangeRequestMessage message = new DhGexKeyExchangeRequestMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserAuthFail(AbstractPacket<BinaryPacket> packet) {
        UserAuthFailureMessage message = new UserAuthFailureMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readGexDHExchangeInitMessage(AbstractPacket<BinaryPacket> packet) {
        DhGexKeyExchangeInitMessage message = new DhGexKeyExchangeInitMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readDhKeyInitMessage(AbstractPacket<BinaryPacket> packet) {
        DhKeyExchangeInitMessage message = new DhKeyExchangeInitMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readDhKeyReplyMessage(AbstractPacket<BinaryPacket> packet) {
        DhKeyExchangeReplyMessage message = new DhKeyExchangeReplyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readGexDHExchangeReplyMessage(AbstractPacket<BinaryPacket> packet) {
        DhGexKeyExchangeReplyMessage message = new DhGexKeyExchangeReplyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKeyExchangeRSAPubkeyMessage(AbstractPacket<BinaryPacket> packet) {
        RsaKeyExchangePubkeyMessage message = new RsaKeyExchangePubkeyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKeyExchangeRSASecret(AbstractPacket<BinaryPacket> packet) {
        RsaKeyExchangeSecretMessage message = new RsaKeyExchangeSecretMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKeyExchangeRSADone(AbstractPacket<BinaryPacket> packet) {
        RsaKeyExchangeDoneMessage message = new RsaKeyExchangeDoneMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserAuthBanner(AbstractPacket<BinaryPacket> packet) {
        UserAuthBannerMessage message = new UserAuthBannerMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserAuthInfoReq(AbstractPacket<BinaryPacket> packet) {
        UserAuthInfoRequestMessage message = new UserAuthInfoRequestMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readUserAuthInfoResp(AbstractPacket<BinaryPacket> packet) {
        UserAuthInfoResponseMessage message = new UserAuthInfoResponseMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readRequestSuccess(AbstractPacket<BinaryPacket> packet) {
        GlobalRequestSuccessMessage message = new GlobalRequestSuccessMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readRequestFailure(AbstractPacket<BinaryPacket> packet) {
        GlobalRequestFailureMessage message = new GlobalRequestFailureMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelWindowsAdjust(AbstractPacket<BinaryPacket> packet) {
        ChannelWindowAdjustMessage message = new ChannelWindowAdjustMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelDataMessage(AbstractPacket<BinaryPacket> packet) {
        ChannelDataMessage message = new ChannelDataMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readServiceRequestData(AbstractPacket<BinaryPacket> packet) {
        ServiceRequestMessage message = new ServiceRequestMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readChannelOpen(AbstractPacket<BinaryPacket> packet) {
        ChannelOpenUnknownMessage channelOpenUnknownMessage = new ChannelOpenUnknownMessage();
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        inputStream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        /*        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }*/
        ChannelOpenUnknownMessageParser parser = new ChannelOpenUnknownMessageParser(inputStream);
        parser.parse(channelOpenUnknownMessage);
        String channelTypeString = channelOpenUnknownMessage.getChannelType().getValue();
        ChannelType channelType = ChannelType.fromName(channelTypeString);
        switch (channelType) {
            case SESSION:
                ChannelOpenSessionMessage channelOpenSessionMessage =
                        new ChannelOpenSessionMessage();
                temp_stream =
                        new HintedInputStreamAdapterStream(
                                null,
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

    private void readMsgServiceAccept(AbstractPacket<BinaryPacket> packet) {
        ServiceAcceptMessage message = new ServiceAcceptMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readHbrReplProtocolData(AbstractPacket<BinaryPacket> packet) {
        HybridKeyExchangeReplyMessage message = new HybridKeyExchangeReplyMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readNewKeysProtocolData(AbstractPacket<BinaryPacket> packet) {
        NewKeysMessage message = new NewKeysMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readKexInitProtocolData(AbstractPacket<BinaryPacket> packet) {
        KeyExchangeInitMessage message = new KeyExchangeInitMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readHbrInitProtocolData(AbstractPacket<BinaryPacket> packet) {
        HybridKeyExchangeInitMessage message = new HybridKeyExchangeInitMessage();
        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
        readContainerFromStream(message, context, temp_stream);
    }

    private void readVersionExchangeProtocolData(AbstractPacket<BlobPacket> packet) {
        VersionExchangeMessage message = new VersionExchangeMessage();

        HintedInputStream temp_stream;

        temp_stream =
                new HintedInputStreamAdapterStream(
                        null, new ByteArrayInputStream(packet.getPayload().getValue()));
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
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        try {
            HintedInputStream dataStream = null;
            dataStream = getLowerLayer().getDataStream();
            if (dataStream.getHint() == null) {
                LOGGER.warn(
                        "The DTLS fragment layer requires a processing hint. E.g. a record type. Parsing as an unknown fragment");
                currentInputStream = new HintedLayerInputStream(null, this);
                currentInputStream.extendStream(dataStream.readAllBytes());
            } else if (dataStream.getHint() instanceof PacketLayerHint) {
                PacketLayerHint tempHint = (PacketLayerHint) dataStream.getHint();
            }
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
            throw ex;
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more dtls fragments", ex);
            throw ex;
        }
    }
}
