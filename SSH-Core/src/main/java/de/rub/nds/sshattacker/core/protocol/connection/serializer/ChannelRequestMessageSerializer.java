/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelRequestMessageSerializer<T extends ChannelRequestMessage<T>>
        extends ChannelMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeRequestType(T object, SerializerStream output) {
        Integer requestTypeLength = object.getRequestTypeLength().getValue();
        LOGGER.debug("Request type length: {}", requestTypeLength);
        output.appendInt(requestTypeLength);
        String requestType = object.getRequestType().getValue();
        LOGGER.debug("Request type: {}", () -> backslashEscapeString(requestType));
        output.appendString(requestType, StandardCharsets.US_ASCII);
    }

    private void serializeWantReply(T object, SerializerStream output) {
        Byte wantReply = object.getWantReply().getValue();
        LOGGER.debug("Want reply: {}", () -> Converter.byteToBoolean(wantReply));
        output.appendByte(wantReply);
    }

    @Override
    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        super.serializeMessageSpecificContents(object, output);
        serializeRequestType(object, output);
        serializeWantReply(object, output);
    }
}
