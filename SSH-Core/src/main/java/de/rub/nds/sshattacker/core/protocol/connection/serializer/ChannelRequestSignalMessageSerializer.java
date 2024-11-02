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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSignalMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelRequestSignalMessageSerializer(ChannelRequestSignalMessage message) {
        super(message);
    }

    private void serializeSignalName() {
        Integer signalNameLength = message.getSignalNameLength().getValue();
        LOGGER.debug("Signal name length: {}", signalNameLength);
        appendInt(signalNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String signalName = message.getSignalName().getValue();
        LOGGER.debug("Signal name: {}", () -> backslashEscapeString(signalName));
        appendString(signalName, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSignalName();
    }
}
