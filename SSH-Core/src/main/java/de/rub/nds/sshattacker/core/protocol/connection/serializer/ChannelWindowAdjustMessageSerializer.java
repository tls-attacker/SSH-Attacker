/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelWindowAdjustMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelWindowAdjustMessageSerializer
        extends ChannelMessageSerializer<ChannelWindowAdjustMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelWindowAdjustMessageSerializer(ChannelWindowAdjustMessage message) {
        super(message);
    }

    private void serializeBytesToAdd() {
        LOGGER.debug("Bytes to add: {}", message.getBytesToAdd().getValue());
        appendInt(message.getBytesToAdd().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeBytesToAdd();
    }
}
