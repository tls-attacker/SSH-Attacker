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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExecMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExecMessageSerializer(ChannelRequestExecMessage message) {
        super(message);
    }

    private void serializeCommand() {
        LOGGER.debug("Command length: {}", message.getCommandLength().getValue());
        appendInt(message.getCommandLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Command: {}", backslashEscapeString(message.getCommand().getValue()));
        appendString(message.getCommand().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeCommand();
    }
}
