/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessageSerializer
        extends ChannelMessageSerializer<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSenderChannel(
            ChannelOpenConfirmationMessage object, SerializerStream output) {
        Integer senderChannelId = object.getSenderChannelId().getValue();
        LOGGER.debug("Sender channel id: {}", senderChannelId);
        output.appendInt(senderChannelId);
    }

    private static void serializeWindowSize(
            ChannelOpenConfirmationMessage object, SerializerStream output) {
        Integer windowSize = object.getWindowSize().getValue();
        LOGGER.debug("Initial window size: {}", windowSize);
        output.appendInt(windowSize);
    }

    private static void serializePacketSize(
            ChannelOpenConfirmationMessage object, SerializerStream output) {
        LOGGER.debug("Maximum packet size: {}", object.getWindowSize().getValue());
        output.appendInt(object.getPacketSize().getValue());
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelOpenConfirmationMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSenderChannel(object, output);
        serializeWindowSize(object, output);
        serializePacketSize(object, output);
    }
}
