/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.impl;

/*import de.rub.nds.sshattacker.core.constants.SSL2MessageType;
import de.rub.nds.sshattacker.core.constants.SSL2TotalHeaderLengths;
import de.rub.nds.sshattacker.core.constants.ssl.SSL2ByteLength;
import de.rub.nds.sshattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.sshattacker.core.exceptions.TimeoutException;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.message.*;*/

import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
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
import de.rub.nds.sshattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.sshattacker.core.protocol.authentication.message.AuthenticationMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ConnectionMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.KeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.UnknownMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage;
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
                /*
                                if (containerAlreadyUsedByHigherLayer(message)
                                        || !prepareDataContainer(message, context)) {
                                    continue;
                                }
                */

                /*MessageLayer messageLayer = context.getMessageLayer();
                AbstractPacket packet = messageLayer.serialize(message);
                Preparator preparator = packet.getPreparator(context);
                preparator.prepare();
                Serializer serializer = packet.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();*/

                LOGGER.debug("[bro] here i am with sending the message");
                /*
                LOGGER.debug(
                        "[bro] MESSAGE: {} {}",
                        message.getProtocolMessageType(),
                        message.getCompleteResultingMessage().getValue());*/

                /*
                                ProtocolMessagePreparator preparator = message.getPreparator(context);
                                preparator.prepare();

                                ProtocolMessageSerializer serializer = message.getSerializer(context);
                                LOGGER.debug("[bro] got serializer");
                                byte[] serializedMessage = serializer.serialize();
                                LOGGER.debug("[bro] serializied the message");
                                message.setCompleteResultingMessage(serializedMessage);
                                LOGGER.debug("[bro] set complete message");
                                ProtocolMessageType protocolMessageType = null;
                                protocolMessageType = message.getProtocolMessageType();

                                LOGGER.debug(
                                        "[bro] Sending Data {} on lower layer {}",
                                        serializedMessage,
                                        getLowerLayer().getLayerType());

                                getLowerLayer()
                                        .sendData(new PacketLayerHint(protocolMessageType), serializedMessage);
                */

                // Es gibt erstmal keine Handshake-Messages mit einer Spezialbehandlung bei SSH
                /*if (!message.isHandshakeMessage()) {
                    // only handshake messages may share a record
                    flushCollectedMessages(runningProtocolMessageType, collectedMessageStream);
                }*/
                runningProtocolMessageType = message.getProtocolMessageType();
                processMessage(message, collectedMessageStream);
                addProducedContainer(message);
                flushCollectedMessages(runningProtocolMessageType, collectedMessageStream);
            }
        }

        if (runningProtocolMessageType == null) {
            LOGGER.debug("[bro] Protocol Message Type is null!");
        } else {
            LOGGER.debug("ProtocolMessageType: {}", runningProtocolMessageType.getValue());
        }

        LOGGER.debug("[bro] " + "flushing {} to lower layer", collectedMessageStream.toByteArray());
        // hand remaining serialized to record layer
        // flushCollectedMessages(runningProtocolMessageType, collectedMessageStream);
        return getLayerResult();

        /*LayerConfiguration<ProtocolMessage> configuration = getLayerConfiguration();
        if (configuration != null && !configuration.getContainerList().isEmpty()) {
            for (ProtocolMessage ssl2message : configuration.getContainerList()) {
                ProtocolMessagePreparator preparator = ssl2message.getPreparator(context);
                preparator.prepare();
                preparator.afterPrepare();
                ssl2message.getHandler(context).adjustContext(ssl2message);
                ProtocolMessageSerializer serializer = ssl2message.getSerializer(context);
                byte[] serializedMessage = serializer.serialize();
                ssl2message.setCompleteResultingMessage(serializedMessage);
                ssl2message.getHandler(context).adjustContextAfterSerialize(ssl2message);
                ssl2message.getHandler(context).updateDigest(ssl2message, true);
                getLowerLayer()
                        .sendData(
                                new RecordLayerHint(ssl2message.getProtocolMessageType()),
                                serializedMessage);
                addProducedContainer(ssl2message);
            }
        }
        return getLayerResult();*/
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

        // Wird nicht benötigt, da wir keinen "Gesamt"-Digest benötigen ?
        // message.getHandler(context).updateDigest(message, true);

        if (message.getCompleteResultingMessage().getValue()[0]
                        == ProtocolMessageType.SSH_MSG_HBR_REPLY.getValue()
                || message.getCompleteResultingMessage().getValue()[0]
                        == ProtocolMessageType.SSH_MSG_KEXINIT.getValue()) {
            message.setAdjustContext(Boolean.FALSE);
        } else {
            LOGGER.info(
                    "[bro] Adjusting Context while messagetype is {}",
                    message.getCompleteResultingMessage().getValue()[0]);
        }

        if (message.getAdjustContext()) {
            message.getHandler(context).adjustContext(message);
        }
        collectedMessageStream.writeBytes(message.getCompleteResultingMessage().getValue());
        // Unklar für SSHv2, erstmal ignoriert
        /*if (mustFlushCollectedMessagesImmediately(message)) {
            flushCollectedMessages(message.getProtocolMessageType(), collectedMessageStream);
        }*/
        if (message.getAdjustContext()) {
            message.getHandler(context).adjustContextAfterSerialize(message);
        }
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

        /*try {
            int messageLength = 0;
            byte paddingLength = 0;
            byte[] totalHeader;
            HintedInputStream dataStream = null;
            SSL2MessageType messageType;
            try {

                dataStream = getLowerLayer().getDataStream();
                totalHeader = dataStream.readNBytes(SSL2ByteLength.LENGTH);

                if (SSL2TotalHeaderLengths.isNoPaddingHeader(totalHeader[0])) {
                    messageLength = resolveUnpaddedMessageLength(totalHeader);
                    paddingLength = 0x00;
                } else {
                    messageLength = resolvePaddedMessageLength(totalHeader);
                    paddingLength = dataStream.readByte();
                }
                messageType = SSL2MessageType.getMessageType(dataStream.readByte());
            } catch (IOException e) {
                LOGGER.warn(
                        "Failed to parse SSL2 message header, parsing as unknown SSL2 message", e);
                messageType = SSL2MessageType.SSL_UNKNOWN;
            }

            SSL2Message message = null;

            switch (messageType) {
                case SSL_CLIENT_HELLO:
                    message = new SSL2ClientHelloMessage();
                    break;
                case SSL_CLIENT_MASTER_KEY:
                    message = new SSL2ClientMasterKeyMessage();
                    break;
                case SSL_SERVER_VERIFY:
                    message = new SSL2ServerVerifyMessage();
                    break;
                case SSL_SERVER_HELLO:
                    message = new SSL2ServerHelloMessage();
                    break;
                default:
                    message = new UnknownSSL2Message();
            }

            message.setType((byte) messageType.getType());
            message.setMessageLength(messageLength);
            message.setPaddingLength((int) paddingLength);
            readDataContainer(message, context);

        } catch (TimeoutException ex) {
            LOGGER.debug(ex);
        } catch (EndOfStreamException ex) {
            LOGGER.debug("Reached end of stream, cannot parse more messages", ex);
        }

        return getLayerResult();*/
    }

    /*private static int resolvePaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_TWO_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }

    private static int resolveUnpaddedMessageLength(final byte[] totalHeaderLength) {
        return (totalHeaderLength[0] & SSL2TotalHeaderLengths.ALL_BUT_ONE_BIT.getValue()) << 8
                | totalHeaderLength[1];
    }*/

    public void readMessageForHint(PacketLayerHint hint) {
        switch (hint.getType()) {
                // use correct parser for the message
                /*            case ALERT:
                    readAlertProtocolData();
                    break;
                case APPLICATION_DATA:
                    readAppDataProtocolData();
                    break;
                case CHANGE_CIPHER_SPEC:
                    readCcsProtocolData(hint.getEpoch());
                    break;
                case HANDSHAKE:
                    readHandshakeProtocolData();
                    break;
                case HEARTBEAT:
                    readHeartbeatProtocolData();
                    break;
                case UNKNOWN:
                    readUnknownProtocolData();
                    break;*/
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
            default:
                LOGGER.error("Undefined record layer type, found type {}", hint.getType());
                break;
        }
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

    /*private void readAlertProtocolData() {
        AlertMessage message = new AlertMessage();
        readDataContainer(message, context);
    }

    private ApplicationMessage readAppDataProtocolData() {
        ApplicationMessage message = new ApplicationMessage();
        readDataContainer(message, context);
        getLowerLayer().removeDrainedInputStream();
        return message;
    }

    private void readCcsProtocolData(Integer epoch) {
        ChangeCipherSpecMessage message = new ChangeCipherSpecMessage();
        if (context.getSelectedProtocolVersion().isDTLS()) {
            if (context.getDtlsReceivedChangeCipherSpecEpochs().contains(epoch)
                    && context.getConfig().isIgnoreRetransmittedCcsInDtls()) {
                message.setAdjustContext(false);
            } else {
                context.addDtlsReceivedChangeCipherSpecEpochs(epoch);
            }
        }
        readDataContainer(message, context);
    }

    */
    /**
     * Parses the handshake layer header from the given message and parses the encapsulated message
     * using the correct parser.
     *
     * @throws IOException
     */
    /*
    private void readHandshakeProtocolData() {
        byte[] readBytes = new byte[0];
        byte type;
        int length;
        byte[] payload;
        HandshakeMessage handshakeMessage;
        HintedInputStream handshakeStream;
        try {
            handshakeStream = getLowerLayer().getDataStream();
            type = handshakeStream.readByte();
            readBytes = ArrayConverter.concatenate(readBytes, new byte[] {type});
            handshakeMessage =
                    MessageFactory.generateHandshakeMessage(
                            HandshakeMessageType.getMessageType(type), context);
            handshakeMessage.setType(type);
            byte[] lengthBytes =
                    handshakeStream.readChunk(HandshakeByteLength.MESSAGE_LENGTH_FIELD);
            length = ArrayConverter.bytesToInt(lengthBytes);
            readBytes = ArrayConverter.concatenate(readBytes, lengthBytes);
            handshakeMessage.setLength(length);
            payload = handshakeStream.readChunk(length);
            readBytes = ArrayConverter.concatenate(readBytes, payload);

        } catch (IOException ex) {
            LOGGER.error("Could not parse message header. Setting bytes as unread: ", ex);
            // not being able to parse the header leaves us with unreadable bytes
            // append instead of replace because we can read multiple messages in one read action
            setUnreadBytes(ArrayConverter.concatenate(this.getUnreadBytes(), readBytes));
            return;
        }
        Handler handler = handshakeMessage.getHandler(context);
        handshakeMessage.setMessageContent(payload);

        try {
            handshakeMessage.setCompleteResultingMessage(
                    ArrayConverter.concatenate(
                            new byte[] {type},
                            ArrayConverter.intToBytes(
                                    length, HandshakeByteLength.MESSAGE_LENGTH_FIELD),
                            payload));
            Parser parser = handshakeMessage.getParser(context, new ByteArrayInputStream(payload));
            parser.parse(handshakeMessage);
            Preparator preparator = handshakeMessage.getPreparator(context);
            preparator.prepareAfterParse(false); // TODO REMOVE THIS CLIENTMODE FLAG
            if (context.getChooser().getSelectedProtocolVersion().isDTLS()) {
                handshakeMessage.setMessageSequence(
                        ((RecordLayerHint) handshakeStream.getHint()).getMessageSequence());
            }
            handshakeMessage.getHandler(context).updateDigest(handshakeMessage, false);
            handler.adjustContext(handshakeMessage);
            addProducedContainer(handshakeMessage);
        } catch (RuntimeException ex) {
            // not being able to handle the handshake message results in an UnknownMessageContainer
            UnknownHandshakeMessage message = new UnknownHandshakeMessage();
            message.setData(payload);
            addProducedContainer(message);
        }
    }

    private void readHeartbeatProtocolData() {
        HeartbeatMessage message = new HeartbeatMessage();
        readDataContainer(message, context);
    }*/

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
                /*if (tempHint.getType() == ProtocolMessageType.HANDSHAKE) {
                    DtlsHandshakeMessageFragment fragment = new DtlsHandshakeMessageFragment();
                    fragment.setEpoch(tempHint.getEpoch());
                    DtlsHandshakeMessageFragmentParser parser =
                            fragment.getParser(
                                    context,
                                    new ByteArrayInputStream(
                                            dataStream.readChunk(dataStream.available())));
                    parser.parse(fragment);
                    fragment.setCompleteResultingMessage(
                            fragment.getSerializer(context).serialize());
                    fragmentManager.addMessageFragment(fragment);
                    List<DtlsHandshakeMessageFragment> uninterpretedMessageFragments =
                            fragmentManager.getOrderedCombinedUninterpretedMessageFragments(
                                    true, false);
                    // run until we received a complete fragment
                    if (!uninterpretedMessageFragments.isEmpty()) {
                        DtlsHandshakeMessageFragment uninterpretedMessageFragment =
                                uninterpretedMessageFragments.get(0);
                        addProducedContainer(uninterpretedMessageFragment);
                        RecordLayerHint currentHint =
                                new RecordLayerHint(
                                        uninterpretedMessageFragment.getProtocolMessageType(),
                                        uninterpretedMessageFragment
                                                .getMessageSequence()
                                                .getValue());
                        byte type = uninterpretedMessageFragment.getType().getValue();
                        byte[] content =
                                uninterpretedMessageFragment.getMessageContent().getValue();
                        byte[] message =
                                ArrayConverter.concatenate(
                                        new byte[] {type},
                                        ArrayConverter.intToBytes(
                                                content.length,
                                                HandshakeByteLength.MESSAGE_LENGTH_FIELD),
                                        content);
                        if (desiredHint == null || currentHint.equals(desiredHint)) {
                            if (currentInputStream == null) {
                                currentInputStream = new HintedLayerInputStream(currentHint, this);
                            } else {
                                currentInputStream.setHint(currentHint);
                            }
                            currentInputStream.extendStream(message);
                        } else {
                            if (nextInputStream == null) {
                                nextInputStream = new HintedLayerInputStream(currentHint, this);
                            } else {
                                nextInputStream.setHint(currentHint);
                            }
                            nextInputStream.extendStream(message);
                        }
                    } else {
                        receiveMoreDataForHint(desiredHint);
                    }
                } else {
                    currentInputStream = new HintedLayerInputStream(tempHint, this);
                    currentInputStream.extendStream(dataStream.readChunk(dataStream.available()));
                }*/
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
