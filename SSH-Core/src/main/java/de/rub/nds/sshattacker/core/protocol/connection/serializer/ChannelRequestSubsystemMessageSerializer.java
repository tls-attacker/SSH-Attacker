/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSubsystemMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSubsystemMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestSubsystemMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSubsystemName(
            ChannelRequestSubsystemMessage object, SerializerStream output) {
        Integer subsystemNameLength = object.getSubsystemNameLength().getValue();
        LOGGER.debug("Subsystem name length: {}", subsystemNameLength);
        output.appendInt(subsystemNameLength);
        String subsystemName = object.getSubsystemName().getValue();
        LOGGER.debug("Subsytem name: {}", () -> backslashEscapeString(subsystemName));
        output.appendString(subsystemName, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestSubsystemMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSubsystemName(object, output);
    }
}
