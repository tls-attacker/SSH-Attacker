/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSubsystemMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestSubsystemMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestSubsystemMessageSerializer(ChannelRequestSubsystemMessage message) {
        super(message);
    }

    public void serializeSubsystemName() {
        LOGGER.debug("Subsystem name length: {}", message.getSubsystemNameLength().getValue());
        appendInt(
                message.getSubsystemNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Subsytem name: {}",
                () -> backslashEscapeString(message.getSubsystemName().getValue()));
        appendString(message.getSubsystemName().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSubsystemName();
    }
}
