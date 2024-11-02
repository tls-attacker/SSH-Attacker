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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSubsystemMessageParser
        extends ChannelRequestMessageParser<ChannelRequestSubsystemMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestSubsystemMessageParser(byte[] array) {
        super(array);
    }

    public ChannelRequestSubsystemMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ChannelRequestSubsystemMessage createMessage() {
        return new ChannelRequestSubsystemMessage();
    }

    private void parseSubsystemName() {
        int subsystemNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setSubsystemNameLength(subsystemNameLength);
        LOGGER.debug("Subsystem name length: {}", subsystemNameLength);
        String subsystemName = parseByteString(subsystemNameLength, StandardCharsets.UTF_8);
        message.setSubsystemName(subsystemName);
        LOGGER.debug("Subsystem name: {}", () -> backslashEscapeString(subsystemName));
    }

    @Override
    protected void parseMessageSpecificContents() {
        super.parseMessageSpecificContents();
        parseSubsystemName();
    }
}
