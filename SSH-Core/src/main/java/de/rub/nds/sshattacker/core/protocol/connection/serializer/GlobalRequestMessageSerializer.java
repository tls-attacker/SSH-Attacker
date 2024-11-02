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
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.message.GlobalRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class GlobalRequestMessageSerializer<T extends GlobalRequestMessage<T>>
        extends SshMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected GlobalRequestMessageSerializer(T message) {
        super(message);
    }

    private void serializeRequestName() {
        Integer requestNameLength = message.getRequestNameLength().getValue();
        LOGGER.debug("Request name length: {}", requestNameLength);
        appendInt(requestNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String requestName = message.getRequestName().getValue();
        LOGGER.debug("Request name: {}", () -> backslashEscapeString(requestName));
        appendString(requestName, StandardCharsets.US_ASCII);
    }

    private void serializeWantReply() {
        Byte wantReply = message.getWantReply().getValue();
        LOGGER.debug("Want reply: {}", () -> Converter.byteToBoolean(wantReply));
        appendByte(wantReply);
    }

    @Override
    protected void serializeMessageSpecificContents() {
        serializeRequestName();
        serializeWantReply();
    }
}
