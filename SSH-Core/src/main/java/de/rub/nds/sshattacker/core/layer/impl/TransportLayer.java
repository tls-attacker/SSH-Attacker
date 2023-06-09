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

import de.rub.nds.sshattacker.core.constants.PacketLayerType;
import de.rub.nds.sshattacker.core.constants.ProtocolMessageType;
import de.rub.nds.sshattacker.core.layer.LayerConfiguration;
import de.rub.nds.sshattacker.core.layer.LayerProcessingResult;
import de.rub.nds.sshattacker.core.layer.ProtocolLayer;
import de.rub.nds.sshattacker.core.layer.constant.ImplementedLayers;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.layer.data.Preparator;
import de.rub.nds.sshattacker.core.layer.data.Serializer;
import de.rub.nds.sshattacker.core.layer.hints.LayerProcessingHint;
import de.rub.nds.sshattacker.core.layer.hints.PacketLayerHint;
import de.rub.nds.sshattacker.core.packet.AbstractPacket;
import de.rub.nds.sshattacker.core.packet.BinaryPacket;
import de.rub.nds.sshattacker.core.packet.BlobPacket;
import de.rub.nds.sshattacker.core.packet.parser.AbstractPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.core.packet.parser.BlobPacketParser;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TransportLayer extends ProtocolLayer<PacketLayerHint, AbstractPacket> {

    private static final Logger LOGGER = LogManager.getLogger();
    private SshContext context;

    public TransportLayer(SshContext context) {
        super(ImplementedLayers.TransportLayer);
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

        LayerConfiguration<AbstractPacket> configuration = getLayerConfiguration();
        if (configuration != null && configuration.getContainerList() != null) {
            for (AbstractPacket packet : configuration.getContainerList()) {
                if (containerAlreadyUsedByHigherLayer(packet) /*|| skipEmptyRecords(session)*/) {
                    continue;
                }

                // MessageLayer messageLayer = context.getMessageLayer();

                try {
                    // AbstractPacket packet = messageLayer.serialize(message);
                    Preparator preparator = packet.getPreparator(context);
                    preparator.prepare();
                    Serializer serializer = packet.getSerializer(context);
                    byte[] serializedMessage = serializer.serialize();

                    LayerProcessingResult layerProcessingResult =
                            getLowerLayer().sendData(null, serializedMessage);

                    /*sendPacket(context, packet);
                    Handler<?> handler = message.getHandler(context);
                    if (handler instanceof MessageSentHandler) {
                        ((MessageSentHandler) handler).adjustContextAfterMessageSent();
                    }
                    return new MessageActionResult(
                            Collections.singletonList(packet), Collections.singletonList(message));*/
                } catch (IOException e) {
                    LOGGER.warn("Error while sending packet: " + e.getMessage());
                    // return new MessageActionResult();
                }
            }

            /*public MessageActionResult sendMessages(
                    SshContext context, Stream<ProtocolMessage<?>> messageStream) {
                return messageStream
                        .map(message -> sendMessage(context, message))
                        .reduce(MessageActionResult::merge)
                        .orElse(new MessageActionResult());
            }*/

            /*                ProtocolMessageType contentType = packet.getContentMessageType();
            if (contentType == null) {
                contentType = ProtocolMessageType.UNKNOWN;
                LOGGER.warn(
                        "Sending record without a LayerProcessing hint. Using \"UNKNOWN\" as the type");
            }
            */
            /*if (encryptor.getRecordCipher(writeEpoch).getState().getVersion().isDTLS()
                    && session.getEpoch() == null) {
                session.setEpoch(writeEpoch);
            }*/
            /*
            if (packet.getCleanProtocolMessageBytes() == null) {
                packet.setCleanProtocolMessageBytes(new byte[0]);
            }
            SessionPreparator preparator =
                    packet.getSessionPreparator(
                            context, */
            /* encryptor, compressor, */
            /* contentType);
                preparator.prepare();
                preparator.afterPrepare();
                SessionSerializer serializer = packet.getSessionSerializer();
                byte[] serializedMessage = serializer.serialize();
                packet.setCompleteRecordBytes(serializedMessage);
                getLowerLayer().sendData(null, serializedMessage);
                addProducedContainer(packet);
            }*/
        }
        return getLayerResult();
    }

    @Override
    public LayerProcessingResult<AbstractPacket> sendData(
            PacketLayerHint hint, byte[] additionalData) throws IOException {
        ProtocolMessageType type = ProtocolMessageType.UNKNOWN;
        if (hint != null) {
            type = hint.getType();
        } else {
            LOGGER.warn(
                    "Sending record without a LayerProcessing hint. Using \"UNKNOWN\" as the type");
        }

        AbstractPacket packet;
        if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            packet = new BlobPacket();
        } else {
            packet = new BinaryPacket();
        }
        packet.setPayload(additionalData);

        Preparator preparator = packet.getPreparator(context);
        preparator.prepare();
        Serializer serializer = packet.getSerializer(context);
        byte[] serializedMessage = serializer.serialize();

        List<AbstractPacket> packets = new LinkedList<>();
        packets.add(packet);

        /*

        List<AbstractPacket> packets = new LinkedList<>();
        List<AbstractPacket> givenPackets = getLayerConfiguration().getContainerList();

        int dataToBeSent = additionalData.length;

        while (givenPackets.size() > 0 && dataToBeSent > 0) {
            AbstractPacket nextPacket = givenPackets.remove(0);
            packets.add(nextPacket);
            */
        /*            int recordData =
                (nextPacket.get() != null
                        ? nextPacket.getMaxRecordLengthConfig()
                        : context.getChooser().getOutboundMaxRecordDataSize());
        dataToBeSent -= recordData;*/
        /*
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();



        // prepare, serialize, and send records
        for (AbstractPacket packet : packets) {
            */
        /*            ProtocolMessageType contentType = packet.getContentMessageType();
        if (contentType == null) {
            contentType = type;
        }*/
        /*
         */
        /*            if (encryptor.getRecordCipher(writeEpoch).getState().getVersion().isDTLS()) {
            record.setEpoch(writeEpoch);
        }*/
        /*
            Preparator preparator = packet.getPreparator(context);
            preparator.prepare();
            preparator.afterPrepare();
            try {
                byte[] recordBytes = packet.getSerializer(context).serialize();
                packet.setCompletePacketBytes(recordBytes);
                stream.write(packet.getCompletePacketBytes().getValue());
            } catch (IOException ex) {
                throw new PreparationException(
                        "Could not write Record bytes to ByteArrayStream", ex);
            }
            addProducedContainer(packet);
        }*/

        getLowerLayer().sendData(null, additionalData);
        return new LayerProcessingResult<>(packets, getLayerType(), true);
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
        throw new UnsupportedOperationException("Not supported yet.");
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

        InputStream dataStream = getLowerLayer().getDataStream();
        AbstractPacketParser parser;
        AbstractPacket packet;

        if (context.getPacketLayerType() == PacketLayerType.BINARY_PACKET) {
            parser =
                    new BinaryPacketParser(
                            dataStream,
                            context.getActiveDecryptCipher(),
                            context.getReadSequenceNumber());
            packet = new BinaryPacket();
        } else if (context.getPacketLayerType() == PacketLayerType.BLOB) {
            parser = new BlobPacketParser(dataStream);
            packet = new BlobPacket();
        } else {
            throw new RuntimeException();
        }

        parser.parse(packet);

        context.getPacketLayer().getDecryptor().decrypt(packet);
        context.getPacketLayer().getDecompressor().decompress(packet);

        addProducedContainer(packet);
    }
}
