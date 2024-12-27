/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelOpenMessageSerializer<T extends ChannelOpenMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeChannelType(T object, SerializerStream output) {
        Integer channelTypeLength = object.getChannelTypeLength().getValue();
        LOGGER.debug("Channel type length: {}", channelTypeLength);
        output.appendInt(channelTypeLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Channel type: {}", object.getChannelType().getValue());
        output.appendString(object.getChannelType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeSenderChannel(T object, SerializerStream output) {
        Integer senderChannelId = object.getSenderChannelId().getValue();
        LOGGER.debug("Sender channel id: {}", senderChannelId);
        output.appendInt(senderChannelId, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeWindowSize(T object, SerializerStream output) {
        Integer windowSize = object.getWindowSize().getValue();
        LOGGER.debug("Initial window size: {}", windowSize);
        output.appendInt(windowSize, DataFormatConstants.UINT32_SIZE);
    }

    private void serializePacketSize(T object, SerializerStream output) {
        Integer packetSize = object.getPacketSize().getValue();
        LOGGER.debug("Maximum packet size: {}", packetSize);
        output.appendInt(packetSize, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeChannelType(object, output);
        serializeSenderChannel(object, output);
        serializeWindowSize(object, output);
        serializePacketSize(object, output);
    }
}
