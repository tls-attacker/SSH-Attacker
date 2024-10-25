/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelWindowAdjustMessageParser
        extends ChannelMessageParser<ChannelWindowAdjustMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelWindowAdjustMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelWindowAdjustMessage message) {
        parseProtocolMessageContents(message);
    }

    private void parseBytesToAdd(ChannelWindowAdjustMessage message) {
        message.setBytesToAdd(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Bytes to add: {}", message.getBytesToAdd().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(ChannelWindowAdjustMessage message) {
        super.parseMessageSpecificContents(message);
        parseBytesToAdd(message);
    }
}
