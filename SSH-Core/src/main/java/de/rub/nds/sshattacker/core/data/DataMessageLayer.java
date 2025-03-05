/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data;

import de.rub.nds.sshattacker.core.constants.ChannelDataType;
import de.rub.nds.sshattacker.core.constants.DataPacketLayerType;
import de.rub.nds.sshattacker.core.data.packet.AbstractDataPacket;
import de.rub.nds.sshattacker.core.data.packet.DataPacket;
import de.rub.nds.sshattacker.core.data.packet.PassThroughPacket;
import de.rub.nds.sshattacker.core.data.packet.layer.*;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessage;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.string.StringDataMessage;
import de.rub.nds.sshattacker.core.data.string.StringDataMessageParser;
import de.rub.nds.sshattacker.core.data.unknown.UnknownDataMessage;
import de.rub.nds.sshattacker.core.data.unknown.UnknownDataMessageParser;
import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelDataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.Optional;
import java.util.stream.Stream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DataMessageLayer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;

    public DataMessageLayer(SshContext context) {
        super();
        this.context = context;
    }

    public DataMessage<?> parse(ChannelDataMessage message) {
        // Query of the expected data type of the channel via which the message was received
        Integer recepientChannelId = message.getRecipientChannelId().getValue();
        Channel channel = context.getChannelManager().getChannelByLocalId(recepientChannelId);
        ChannelDataType dataType;
        if (channel == null) {
            dataType = ChannelDataType.UNKNOWN;
            LOGGER.warn(
                    "ChannelDataMessage received but no channel with id {} found locally, processing it as unknown data.",
                    recepientChannelId);
        } else {
            dataType = channel.getExpectedDataType();
        }

        // Create correct data packet layer for expected data type
        DataPacketLayerType layerType =
                switch (dataType) {
                    case AUTH_AGENT, SUBSYSTEM_SFTP -> DataPacketLayerType.DATA;
                    case SHELL -> DataPacketLayerType.PASS_THROUGH;
                    default -> {
                        LOGGER.warn(
                                "Channel expected data type set to {}, but there is no packet layer implemented for it. Fall back to pass-through packet layer.",
                                dataType);
                        yield DataPacketLayerType.PASS_THROUGH;
                    }
                };
        AbstractDataPacketLayer packetLayer =
                DataPacketLayerFactory.getDataPacketLayer(layerType, context);

        // Parse the packet according to expected data type
        DataPacketLayerParseResult parseResult =
                packetLayer.parsePacketSoftly(message.getData().getValue(), 0);
        if (parseResult.getParsedByteCount() < message.getDataLength().getValue()) {
            LOGGER.debug(
                    "Data packet did not consume complete channel data. Only parsed {} of {} bytes.",
                    parseResult.getParsedByteCount(),
                    message.getDataLength().getValue());
        }
        Optional<AbstractDataPacket> parsedPacket = parseResult.getParsedPacket();
        if (parsedPacket.isPresent()) {
            // Parse and return the message according to expected data type
            DataMessage<?> resultMessage;
            try {
                resultMessage =
                        switch (dataType) {
                            case SUBSYSTEM_SFTP ->
                                    SftpMessageParser.delegateParsing(parsedPacket.get(), context);
                            case SHELL ->
                                    new StringDataMessageParser(
                                                    parsedPacket.get().getPayload().getValue())
                                            .parse();
                            default -> {
                                LOGGER.debug(
                                        "No parser implemented for ChannelDataType: {}", dataType);
                                yield new UnknownDataMessageParser(
                                                parsedPacket.get().getPayload().getValue())
                                        .parse();
                            }
                        };
            } catch (ParserException ex) {
                LOGGER.warn("{}. Parsing as UnknownDataMessage", ex::getMessage);
                resultMessage =
                        new UnknownDataMessageParser(parsedPacket.get().getPayload().getValue())
                                .parse();
            }

            // If the data message body was empty
            int resultMessageLength = resultMessage.getCompleteResultingMessage().getValue().length;
            int packetPayloadLength = parsedPacket.get().getPayload().getValue().length;
            if (resultMessageLength < packetPayloadLength) {
                // This usually means that we have not implemented the parser for the negotiated
                // SFTP version, or we received malformed responses. Especially length of malformed
                // filenames are often wrong.
                LOGGER.debug(
                        "Data message [{}] did not consume complete data packet. Only parsed {} of {} bytes.",
                        resultMessage.getClass().getSimpleName(),
                        resultMessageLength,
                        packetPayloadLength);
            }
            resultMessage.setChannelDataWrapper(message);
            return resultMessage;
        }
        LOGGER.warn("Parsing as UnknownDataMessage");
        UnknownDataMessage unknownResult =
                new UnknownDataMessageParser(message.getData().getValue()).parse();
        unknownResult.setChannelDataWrapper(message);
        return unknownResult;
    }

    public Stream<DataMessage<?>> parse(
            Stream<ChannelDataMessage> dataMessageStream, ChannelDataType dataType) {
        return dataMessageStream.map(this::parse);
    }

    public ChannelDataMessage serialize(DataMessage<?> message) {
        // Create DataPacket and set serialized message as payload
        AbstractDataPacket packet;
        AbstractDataPacketLayer packetLayer;
        if (message instanceof SftpMessage) {
            packet = new DataPacket();
            packetLayer = new DataPacketLayer(context);
        } else if (message instanceof StringDataMessage) {
            packet = new PassThroughPacket();
            packetLayer = new PassThroughPacketLayer(context);
        } else {
            // Unknown Data Messages
            packet = new PassThroughPacket();
            packetLayer = new PassThroughPacketLayer(context);
        }
        packet.setPayload(message.serialize());

        // Create and prepare ChannelDataMessage
        ChannelDataMessage resultMessage = new ChannelDataMessage();
        resultMessage.prepare(context.getChooser());

        // Set prepared and serialized packet as data of ChannelDataMessage
        resultMessage.setData(packetLayer.preparePacket(packet), true);

        // TODO: If more than one channel is open:
        //  Try to set recipientChannelId to channel that expect that data type

        return resultMessage;
    }

    public Stream<ChannelDataMessage> serialize(Stream<DataMessage<?>> messageStream) {
        return messageStream.map(this::serialize);
    }
}
