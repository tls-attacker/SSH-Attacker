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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public abstract class ChannelOpenMessageSerializer<T extends ChannelOpenMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenMessageSerializer(T message) {
        super(message);
    }

    private void serializeChannelType() {
        LOGGER.debug("Channel type length: " + message.getChannelTypeLength().getValue());
        appendInt(
                message.getChannelTypeLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Channel type: " + message.getChannelType().getValue());
        appendString(message.getChannelType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeSenderChannel() {
        LOGGER.debug("Sender channel id: " + message.getSenderChannelId().getValue());
        appendInt(message.getSenderChannelId().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializeWindowSize() {
        LOGGER.debug("Initial window size: " + message.getWindowSize().getValue());
        appendInt(message.getWindowSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    private void serializePacketSize() {
        LOGGER.debug("Maximum packet size: " + message.getPacketSize().getValue());
        appendInt(message.getPacketSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeChannelType();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
    }
}
