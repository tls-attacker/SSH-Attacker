/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelOpenMessageSerializer<T extends ChannelOpenMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelOpenMessageSerializer(T message) {
        super(message);
    }

    private void serializeChannelType() {
        Integer channelTypeLength = message.getChannelTypeLength().getValue();
        LOGGER.debug("Channel type length: {}", channelTypeLength);
        appendInt(channelTypeLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Channel type: {}", message.getChannelType().getValue());
        appendString(message.getChannelType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeSenderChannel() {
        Integer senderChannelId = message.getSenderChannelId().getValue();
        LOGGER.debug("Sender channel id: {}", senderChannelId);
        appendInt(senderChannelId, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeWindowSize() {
        Integer windowSize = message.getWindowSize().getValue();
        LOGGER.debug("Initial window size: {}", windowSize);
        appendInt(windowSize, DataFormatConstants.UINT32_SIZE);
    }

    private void serializePacketSize() {
        Integer packetSize = message.getPacketSize().getValue();
        LOGGER.debug("Maximum packet size: {}", packetSize);
        appendInt(packetSize, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeChannelType();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
    }
}
