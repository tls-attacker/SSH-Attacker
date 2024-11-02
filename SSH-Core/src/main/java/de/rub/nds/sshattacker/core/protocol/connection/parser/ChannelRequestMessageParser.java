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
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelRequestMessageParser<T extends ChannelRequestMessage<T>>
        extends ChannelMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ChannelRequestMessageParser(byte[] array) {
        super(array);
    }

    protected ChannelRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseRequestType() {
        int requestTypeLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setRequestTypeLength(requestTypeLength);
        LOGGER.debug("Request type length: {}", requestTypeLength);
        String requestType = parseByteString(requestTypeLength, StandardCharsets.US_ASCII);
        message.setRequestType(requestType);
        LOGGER.debug("Request type: {}", requestType);
    }

    private void parseWantReply() {
        byte wantReply = parseByteField(1);
        message.setWantReply(wantReply);
        LOGGER.debug("Reply wanted: {}", Converter.byteToBoolean(wantReply));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseRequestType();
        parseWantReply();
    }
}
