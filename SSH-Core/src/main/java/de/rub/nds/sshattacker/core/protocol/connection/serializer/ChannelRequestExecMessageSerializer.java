/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExecMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class ChannelRequestExecMessageSerializer extends ChannelRequestMessageSerializer<ChannelRequestExecMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExecMessageSerializer(ChannelRequestExecMessage msg) {
        super(msg);
    }

    private void serializeCommand() {
        LOGGER.debug("Command length: " + msg.getCommandLength().getValue());
        appendInt(msg.getCommandLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Command: " + msg.getCommand().getValue());
        appendString(msg.getCommand().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificPayload() {
        super.serializeMessageSpecificPayload();
        serializeCommand();
    }
}
