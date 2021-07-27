/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public abstract class ChannelRequestMessageParser<T extends ChannelRequestMessage<T>> extends ChannelMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestMessageParser(int startPosition, byte[] array) {
        super(startPosition, array);
    }

    private void parseRequestType(T msg) {
        msg.setRequestTypeLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Request type length: " + msg.getRequestTypeLength().getValue());
        msg.setRequestType(parseByteString(msg.getRequestTypeLength().getValue(), StandardCharsets.US_ASCII), false);
        LOGGER.debug("Request type: " + msg.getRequestType().getValue());
    }

    private void parseWantReply(T msg) {
        msg.setWantReply(parseByteField(1));
        LOGGER.debug("Reply wanted: " + Converter.byteToBoolean(msg.getWantReply().getValue()));
    }

    @Override
    protected void parseMessageSpecificPayload(T msg) {
        super.parseMessageSpecificPayload(msg);
        parseRequestType(msg);
        parseWantReply(msg);
    }
}
