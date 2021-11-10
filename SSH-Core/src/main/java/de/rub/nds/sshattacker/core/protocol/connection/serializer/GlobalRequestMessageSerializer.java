/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

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

    public GlobalRequestMessageSerializer(T message) {
        super(message);
    }

    protected void serializeRequestName() {
        LOGGER.debug("Request name length: " + message.getRequestNameLength().getValue());
        appendInt(
                message.getRequestNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Request name: " + message.getRequestName().getValue());
        appendString(message.getRequestName().getValue(), StandardCharsets.US_ASCII);
    }

    protected void serializeWantReply() {
        LOGGER.debug("Want reply: " + Converter.byteToBoolean(message.getWantReply().getValue()));
        appendByte(message.getWantReply().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeRequestName();
        serializeWantReply();
    }
}
