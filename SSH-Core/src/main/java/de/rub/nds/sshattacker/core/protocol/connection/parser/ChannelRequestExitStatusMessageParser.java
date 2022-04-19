/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitStatusMessageParser
        extends ChannelRequestMessageParser<ChannelRequestExitStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitStatusMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestExitStatusMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestExitStatusMessage createMessage() {
        return new ChannelRequestExitStatusMessage();
    }

    public void parseExitStatus() {
        message.setExitStatus(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Exit status: " + message.getExitStatus().getValue());
    }

    public void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseExitStatus();
    }
}
