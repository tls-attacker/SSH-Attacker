/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestExitStatusMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestExitStatusMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestExitStatusMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestExitStatusMessageSerializer(ChannelRequestExitStatusMessage message) {
        super(message);
    }

    private void serializeExitStatus() {
        LOGGER.debug("Exit status: {}", message.getExitStatus().getValue());
        appendInt(message.getExitStatus().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeExitStatus();
    }
}
