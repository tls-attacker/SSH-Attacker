/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSignalMessageParser
        extends ChannelRequestMessageParser<ChannelRequestSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestSignalMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestSignalMessageParser(byte[] array, Integer startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestSignalMessage createMessage() {
        return new ChannelRequestSignalMessage();
    }

    public void parseSignalName() {
        message.setSignalNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Signal name length: {}", message.getSignalNameLength().getValue());
        message.setSignalName(parseByteString(message.getSignalNameLength().getValue()));
        LOGGER.debug("Signal name: {}", backslashEscapeString(message.getSignalName().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSignalName();
    }
}
