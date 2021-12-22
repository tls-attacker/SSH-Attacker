/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
        LOGGER.debug("Sender channel: " + message.getModSenderChannel().getValue());
        appendInt(message.getModSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeWindowSize() {
        LOGGER.debug("Initial window size: " + message.getWindowSize().getValue());
        appendInt(message.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePacketSize() {
        LOGGER.debug("Maximum packet size: " + message.getWindowSize().getValue());
        appendInt(message.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
    }
}
