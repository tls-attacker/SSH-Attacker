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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestSignalMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestSignalMessageSerializer
        extends ChannelRequestMessageSerializer<ChannelRequestSignalMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeSignalName(
            ChannelRequestSignalMessage object, SerializerStream output) {
        Integer signalNameLength = object.getSignalNameLength().getValue();
        LOGGER.debug("Signal name length: {}", signalNameLength);
        output.appendInt(signalNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String signalName = object.getSignalName().getValue();
        LOGGER.debug("Signal name: {}", () -> backslashEscapeString(signalName));
        output.appendString(signalName, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeMessageSpecificContents(
            ChannelRequestSignalMessage object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeSignalName(object, output);
    }
}
