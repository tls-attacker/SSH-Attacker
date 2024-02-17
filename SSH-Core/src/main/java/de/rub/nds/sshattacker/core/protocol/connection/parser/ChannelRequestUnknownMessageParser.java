/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestUnknownMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestUnknownMessageParser
        extends ChannelRequestMessageParser<ChannelRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    /*
        public ChannelRequestUnknownMessageParser(byte[] array) {
            super(array);
        }
        public ChannelRequestUnknownMessageParser(byte[] array, int startPosition) {
            super(array, startPosition);
        }
    */

    public ChannelRequestUnknownMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestUnknownMessage message) {
        parseProtocolMessageContents(message);
        message.setCompleteResultingMessage(getAlreadyParsed());
    }

    /*
        @Override
        public ChannelRequestUnknownMessage createMessage() {
            return new ChannelRequestUnknownMessage();
        }
    */

    public void parseTypeSpecificData(ChannelRequestUnknownMessage message) {
        message.setTypeSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Type specific data: {}",
                ArrayConverter.bytesToHexString(message.getTypeSpecificData().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestUnknownMessage message) {
        super.parseMessageSpecificContents(message);
        parseTypeSpecificData(message);
    }
}
