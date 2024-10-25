/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExecMessageParser
        extends ChannelRequestMessageParser<ChannelRequestExecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExecMessageParser(InputStream stream) {
        super(stream);
    }

    @Override
    public void parse(ChannelRequestExecMessage message) {
        parseProtocolMessageContents(message);
    }

    public void parseCommand(ChannelRequestExecMessage message) {
        message.setCommandLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Command length: {}", message.getCommandLength().getValue());
        message.setCommand(parseByteString(message.getCommandLength().getValue()));
        LOGGER.debug("Command: {}", message.getCommand().getValue());
    }

    @Override
    protected void parseMessageSpecificContents(ChannelRequestExecMessage message) {
        super.parseMessageSpecificContents(message);
        parseCommand(message);
    }
}
