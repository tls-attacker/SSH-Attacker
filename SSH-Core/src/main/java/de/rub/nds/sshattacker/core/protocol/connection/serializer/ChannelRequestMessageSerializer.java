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
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public abstract class ChannelRequestMessageSerializer<T extends ChannelRequestMessage<T>> extends
        ChannelMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestMessageSerializer(T msg) {
        super(msg);
    }

    private void serializeRequestType() {
        LOGGER.debug("Request type length: " + msg.getRequestTypeLength().getValue());
        appendInt(msg.getRequestTypeLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Request type: " + msg.getRequestType().getValue());
        appendString(msg.getRequestType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeWantReply() {
        LOGGER.debug("Want reply: " + Converter.byteToBoolean(msg.getWantReply().getValue()));
        appendByte(msg.getWantReply().getValue());
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeRequestType();
        serializeWantReply();
    }

}
