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
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestBreakMessageParser
        extends ChannelRequestMessageParser<ChannelRequestBreakMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public ChannelRequestBreakMessageParser(byte[] array) {
            super(array);
        }
        public ChannelRequestBreakMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelRequestBreakMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestBreakMessage message) {
        parseMessageSpecificContents(message);
    }

    /* @Override
        public ChannelRequestBreakMessage createMessage() {
            return new ChannelRequestBreakMessage();
        }
    */
    public void parseBreakLength(ChannelRequestBreakMessage message) {
        message.setBreakLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Break length in milliseconds: " + message.getBreakLength().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestBreakMessage message) {
        super.parseMessageSpecificContents(message);
        parseBreakLength(message);
    }
}
