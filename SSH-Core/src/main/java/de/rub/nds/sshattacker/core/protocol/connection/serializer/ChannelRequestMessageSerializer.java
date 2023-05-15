/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelRequestMessageSerializer<T extends ChannelRequestMessage<T>>
        extends ChannelMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelRequestMessageSerializer(T message) {
        super(message);
    }

    private void serializeRequestType() {
        LOGGER.debug("Request type length: {}", message.getRequestTypeLength().getValue());
        appendInt(
                message.getRequestTypeLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Request type: {}", message.getRequestType().getValue());
        appendString(message.getRequestType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeWantReply() {
        LOGGER.debug("Want reply: {}", Converter.byteToBoolean(message.getWantReply().getValue()));
        appendByte(message.getWantReply().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeRequestType();
        serializeWantReply();
    }
}
