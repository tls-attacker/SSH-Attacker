/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageSerializer
        extends ChannelMessageSerializer<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageSerializer(ChannelOpenConfirmationMessage message) {
        super(message);
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
        LOGGER.debug("Maximum packet size: {}", message.getWindowSize().getValue());
        appendInt(message.getPacketSize().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
    }
}
