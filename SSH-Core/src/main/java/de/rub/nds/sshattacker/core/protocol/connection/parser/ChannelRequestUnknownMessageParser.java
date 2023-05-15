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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestUnknownMessageParser
        extends ChannelRequestMessageParser<ChannelRequestUnknownMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestUnknownMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestUnknownMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestUnknownMessage createMessage() {
        return new ChannelRequestUnknownMessage();
    }

    public void parseTypeSpecificData() {
        message.setTypeSpecificData(parseByteArrayField(getBytesLeft()));
        LOGGER.debug(
                "Type specific data: {}",
                ArrayConverter.bytesToHexString(message.getTypeSpecificData().getValue()));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseTypeSpecificData();
    }
}
