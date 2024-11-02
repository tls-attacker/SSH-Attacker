/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestBreakMessageParser
        extends ChannelRequestMessageParser<ChannelRequestBreakMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestBreakMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestBreakMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestBreakMessage createMessage() {
        return new ChannelRequestBreakMessage();
    }

    private void parseBreakLength() {
        int breakLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setBreakLength(breakLength);
        LOGGER.debug("Break length in milliseconds: {}", breakLength);
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseBreakLength();
    }
}
