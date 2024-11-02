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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestMessageSerializer<T extends ChannelRequestMessage<T>>
        extends ChannelMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelRequestMessageSerializer(T message) {
        super(message);
    }

    private void serializeRequestType() {
        Integer requestTypeLength = message.getRequestTypeLength().getValue();
        LOGGER.debug("Request type length: {}", requestTypeLength);
        appendInt(requestTypeLength, DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Request type: {}", message.getRequestType().getValue());
        appendString(message.getRequestType().getValue(), StandardCharsets.US_ASCII);
    }

    private void serializeWantReply() {
        Byte wantReply = message.getWantReply().getValue();
        LOGGER.debug("Want reply: {}", () -> Converter.byteToBoolean(wantReply));
        appendByte(wantReply);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeRequestType();
        serializeWantReply();
    }
}
