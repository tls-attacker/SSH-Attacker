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

import de.rub.nds.sshattacker.core.exceptions.EndOfStreamException;
import de.rub.nds.sshattacker.core.exceptions.TimeoutException;
import de.rub.nds.sshattacker.core.layer.LayerProcessingResult;
import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.sshattacker.core.layer.hints.RecordLayerHint;
import de.rub.nds.sshattacker.core.layer.stream.HintedInputStream;
import de.rub.nds.sshattacker.core.layer.stream.HintedLayerInputStream;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ConnectionLayer extends ProtocolLayer<LayerProcessingHint, ProtocolMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public ConnectionLayer(SshContext context) {
        super(ImplementedLayers.ConnectionLayer);
        this.context = context;
    }

    @Override
    public LayerProcessingResult sendConfiguration() throws IOException {
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
        return null;
    }

    @Override
    public LayerProcessingResult sendData(LayerProcessingHint hint, byte[] additionalData)
            throws IOException {
        return sendConfiguration();
    }

    @Override
    public LayerProcessingResult receiveData() {

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
        return null;
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
    public void receiveMoreDataForHint(LayerProcessingHint hint) throws IOException {
        try {
            HintedInputStream dataStream = null;
            dataStream = getLowerLayer().getDataStream();
            if (dataStream.getHint() == null) {
                LOGGER.warn(
                        "The DTLS fragment layer requires a processing hint. E.g. a record type. Parsing as an unknown fragment");
                currentInputStream = new HintedLayerInputStream(null, this);
                currentInputStream.extendStream(dataStream.readAllBytes());
            } else if (dataStream.getHint() instanceof RecordLayerHint) {
                RecordLayerHint tempHint = (RecordLayerHint) dataStream.getHint();
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
