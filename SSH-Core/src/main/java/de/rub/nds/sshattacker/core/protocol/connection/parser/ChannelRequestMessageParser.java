/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelRequestMessageParser<T extends ChannelRequestMessage<T>>
        extends ChannelMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestMessageParser(InputStream stream) {
        super(stream);
    }

    private void parseRequestType(T message) {
        message.setRequestTypeLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Request type length: {}", message.getRequestTypeLength().getValue());
        message.setRequestType(
                parseByteString(
                        message.getRequestTypeLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Request type: {}", message.getRequestType().getValue());
    }

    private void parseWantReply(T message) {
        message.setWantReply(parseByteField(1));
        LOGGER.debug(
                "Reply wanted: {}", Converter.byteToBoolean(message.getWantReply().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(T message) {
        super.parseMessageSpecificContents(message);
        parseRequestType(message);
        parseWantReply(message);
    }
}
