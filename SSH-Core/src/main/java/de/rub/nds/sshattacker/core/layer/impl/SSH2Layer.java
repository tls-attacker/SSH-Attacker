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
import de.rub.nds.sshattacker.core.protocol.authentication.message.*;
import de.rub.nds.sshattacker.core.protocol.authentication.parser.*;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelOpenUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.parser.GlobalRequestUnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SSH2Layer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public SSH2Layer(SshContext context) {
        super(ImplementedLayers.SSHv2);
        this.context = context;
    }

    private void flushCollectedMessages(
            ProtocolMessageType runningProtocolMessageType, ByteArrayOutputStream byteStream)
            throws IOException {

        LOGGER.debug(
                "[bro] Sending the following {} on {}",
                byteStream.toByteArray(),
                getLowerLayer().getLayerType());
        if (byteStream.size() > 0) {
            getLowerLayer()
                    .sendData(
                            new PacketLayerHint(runningProtocolMessageType),
                            byteStream.toByteArray());
            byteStream.reset();
        }
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
        LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        ProtocolMessageType runningProtocolMessageType = null;
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

                runningProtocolMessageType = message.getProtocolMessageType();
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
            LOGGER.debug("ProtocolMessageType: {}", runningProtocolMessageType.getValue());
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

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData)
            throws IOException {
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
                LOGGER.debug("[bro] Searching for Hint");
                LayerProcessingHint tempHint = dataStream.getHint();
                if (tempHint == null) {
                    LOGGER.warn(
                            "The TLS message layer requires a processing hint. E.g. a record type. Parsing as an unknown message");
                    readUnknownProtocolData();
                } else if (tempHint instanceof PacketLayerHint) {
                    PacketLayerHint hint = (PacketLayerHint) dataStream.getHint();
                    readMessageForHint(hint);
                }
                // receive until the layer configuration is satisfied or no data is left
            } while (shouldContinueProcessing());
        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
        }

        return getLayerResult();
    }

    public void readMessageForHint(PacketLayerHint hint) {
        switch (hint.getType()) {
                // use correct parser for the message

            case AUTHENTICATION:
                readAuthenticationProtocolData();
                break;
            case CONNECTION:
                readConnectionProtocolData();
                break;
            case VERSION_EXCHANGE_MESSAGE:
                readVersionExchangeProtocolData();
                break;
            case SSH_MSG_KEXINIT:
                readKexInitProtocolData();
                break;
            case SSH_MSG_HBR_INIT:
                readHbrInitProtocolData();
                break;
            case SSH_MSG_NEWKEYS:
                readNewKeysProtocolData();
                break;
            case SSH_MSG_SERVICE_REQUEST:
                readServiceRequestData();
                break;
            case SSH_MSG_HBR_REPLY:
                readHbrReplProtocolData();
                break;
            case SSH_MSG_SERVICE_ACCEPT:
                readMsgServiceAccept();
                break;
            case SSH_MSG_USERAUTH_REQUEST:
                readUserAuthReq();
                break;
            case SSH_MSG_CHANNEL_OPEN:
                readChannelOpen();
                break;
            case SSH_MSG_CHANNEL_REQUEST:
                readChannelRequest();
                break;
            case SSH_MSG_GLOBAL_REQUEST:
                readGlobalRequest();
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
                readUserAuthSucc();
                break;
            case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                readChannelOpenConfirmation();
                break;
            case SSH_MSG_CHANNEL_CLOSE:
                readChannelCloseMessage();
                break;
            case SSH_MSG_CHANNEL_EOF:
                readChannelEofMessage();
                break;
            case SSH_MSG_CHANNEL_EXTENDED_DATA:
                readChannelExtendedDataMessage();
                break;
            case SSH_MSG_CHANNEL_FAILURE:
                readChannelFailureMessage();
                break;
            case SSH_MSG_CHANNEL_OPEN_FAILURE:
                readChannelOpenFailureMessage();
                break;
            case SSH_MSG_CHANNEL_SUCCESS:
                readChannelSuccessMessage();
                break;
            case SSH_MSG_IGNORE:
                readIngoreMessage();
                break;
            case SSH_MSG_KEX_ECDH_REPLY:
                readKexECDHReply();
                break;
            case SSH_MSG_KEX_ECDH_INIT:
                readKexECDHInit();
                break;
/*           Not Implementended Yet
             case SSH_MSG_EXT_INFO:
                readExtensionInfo();
                break;*/
            default:
                LOGGER.error("Undefined record layer type, found type {}", hint.getType());
                throw new RuntimeException();
                // break;
        }
    }

    private void readUserAuthReq() {
        UserAuthUnknownMessage userAuthUnknownMessage = new UserAuthUnknownMessage();
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }

        /* int length = 0;

        try {
            length = inputStream.available();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        try {
            LOGGER.info("remainign in Inpustream: {}", inputStream.available());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] data = new byte[length];

        try {
            inputStream.read(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        HintedInputStream copied_inputstream = new HintedInputStreamAdapterStream(null, new ByteArrayInputStream(data)); */

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

    private void readChannelRequest() {
        ChannelRequestUnknownMessage channelRequestUnknownMessage =
                new ChannelRequestUnknownMessage();
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }

        /* int length = 0;

        try {
            length = inputStream.available();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }


        try {
            LOGGER.info("remainign in Inpustream: {}", inputStream.available());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        byte[] data = new byte[length];

        try {
            inputStream.read(data);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        HintedInputStream copied_inputstream = new HintedInputStreamAdapterStream(null, new ByteArrayInputStream(data)); */

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

    private void readGlobalRequest() {
        GlobalRequestUnknownMessage globalRequestUnknownMessage = new GlobalRequestUnknownMessage();
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }
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

    private void readIngoreMessage() {
        ChannelSuccessMessage message = new ChannelSuccessMessage();
        readDataContainer(message, context);
    }


    private void readKexECDHInit() {
        EcdhKeyExchangeInitMessage message = new EcdhKeyExchangeInitMessage();
        readDataContainer(message, context);
    }

    private void readKexECDHReply() {
        EcdhKeyExchangeReplyMessage message = new EcdhKeyExchangeReplyMessage();
        readDataContainer(message, context);
    }

    private void readChannelSuccessMessage() {
        ChannelSuccessMessage message = new ChannelSuccessMessage();
        readDataContainer(message, context);
    }

    private void readChannelCloseMessage() {
        ChannelCloseMessage message = new ChannelCloseMessage();
        readDataContainer(message, context);
    }

    private void readChannelEofMessage() {
        ChannelEofMessage message = new ChannelEofMessage();
        readDataContainer(message, context);
    }

    private void readChannelExtendedDataMessage() {
        ChannelExtendedDataMessage message = new ChannelExtendedDataMessage();
        readDataContainer(message, context);
    }

    private void readChannelFailureMessage() {
        ChannelFailureMessage message = new ChannelFailureMessage();
        readDataContainer(message, context);
    }

    private void readChannelOpenFailureMessage() {
        ChannelOpenFailureMessage message = new ChannelOpenFailureMessage();
        readDataContainer(message, context);
    }

    private void readChannelOpenConfirmation() {
        ChannelOpenConfirmationMessage message = new ChannelOpenConfirmationMessage();
        readDataContainer(message, context);
    }

    private void readUserAuthSucc() {
        UserAuthSuccessMessage message = new UserAuthSuccessMessage();
        readDataContainer(message, context);
    }

    private void readServiceRequestData() {
        ServiceRequestMessage message = new ServiceRequestMessage();
        readDataContainer(message, context);
    }

    private void readChannelOpen() {
        ChannelOpenUnknownMessage channelOpenUnknownMessage = new ChannelOpenUnknownMessage();
        HintedInputStream inputStream;
        HintedInputStream temp_stream;
        try {
            inputStream = getLowerLayer().getDataStream();
        } catch (IOException e) {
            LOGGER.warn("The lower layer did not produce a data stream: ", e);
            return;
        }
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

    private void readMsgServiceAccept() {
        ServiceAcceptMessage message = new ServiceAcceptMessage();
        readDataContainer(message, context);
    }

    private void readHbrReplProtocolData() {
        HybridKeyExchangeReplyMessage message = new HybridKeyExchangeReplyMessage();
        readDataContainer(message, context);
    }

    private void readNewKeysProtocolData() {
        NewKeysMessage message = new NewKeysMessage();
        readDataContainer(message, context);
    }

    private void readAuthenticationProtocolData() {
        AuthenticationMessage message = new AuthenticationMessage();
        readDataContainer(message, context);
    }

    private void readKexInitProtocolData() {
        KeyExchangeInitMessage message = new KeyExchangeInitMessage();
        readDataContainer(message, context);
    }

    private void readHbrInitProtocolData() {
        HybridKeyExchangeInitMessage message = new HybridKeyExchangeInitMessage();
        readDataContainer(message, context);
    }

    private void readVersionExchangeProtocolData() {
        VersionExchangeMessage message = new VersionExchangeMessage();
        readDataContainer(message, context);
    }

    private void readConnectionProtocolData() {
        ConnectionMessage message = new ConnectionMessage();
        readDataContainer(message, context);
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
