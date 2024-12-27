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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExecMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeCommand(
            ChannelRequestExecMessage object, SerializerStream output) {
        Integer commandLength = object.getCommandLength().getValue();
        LOGGER.debug("Command length: {}", commandLength);
        output.appendInt(commandLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String command = object.getCommand().getValue();
        LOGGER.debug("Command: {}", () -> backslashEscapeString(command));
        output.appendString(command, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestExecMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeCommand(object, output);
    }
}
