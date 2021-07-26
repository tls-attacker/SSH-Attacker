/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageSerializer extends ChannelMessageSerializer<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessageSerializer(ChannelOpenConfirmationMessage msg) {
        super(msg);
    }

    private void serializeSenderChannel() {
        LOGGER.debug("Sender channel: " + msg.getSenderChannel().getValue());
        appendInt(msg.getSenderChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeWindowSize() {
        LOGGER.debug("Initial window size: " + msg.getWindowSize().getValue());
        appendInt(msg.getWindowSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializePacketSize() {
        LOGGER.debug("Maximum packet size: " + msg.getWindowSize().getValue());
        appendInt(msg.getPacketSize().getValue(), DataFormatConstants.INT32_SIZE);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeSenderChannel();
        serializeWindowSize();
        serializePacketSize();
        return getAlreadySerialized();
    }

}
