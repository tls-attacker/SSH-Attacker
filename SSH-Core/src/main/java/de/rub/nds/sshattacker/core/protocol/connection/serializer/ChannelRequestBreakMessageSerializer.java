/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestBreakMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestBreakMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestBreakMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeBreakLength(
            ChannelRequestBreakMessage object, SerializerStream output) {
        Integer breakLength = object.getBreakLength().getValue();
        LOGGER.debug("Break length in milliseconds: {}", breakLength);
        output.appendInt(breakLength);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestBreakMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeBreakLength(object, output);
    }
}
