/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

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

    public void serializeSignalName() {
        LOGGER.debug("Signal name length: " + message.getSignalNameLength().getValue());
        appendInt(message.getSignalNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signal name: " + message.getSignalName().getValue());
        appendString(message.getSignalName().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeSignalName();
    }
}
