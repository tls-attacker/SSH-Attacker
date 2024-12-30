/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExtendedMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedMessageSerializer<T extends SftpRequestExtendedMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeExtendedRequestName(T object, SerializerStream output) {
        Integer extendedRequestNameLength = object.getExtendedRequestNameLength().getValue();
        LOGGER.debug("ExtendedRequestName length: {}", extendedRequestNameLength);
        output.appendInt(extendedRequestNameLength);
        String extendedRequestName = object.getExtendedRequestName().getValue();
        LOGGER.debug("ExtendedRequestName: {}", () -> backslashEscapeString(extendedRequestName));
        output.appendString(extendedRequestName, StandardCharsets.US_ASCII);
    }

    @Override
    protected void serializeRequestSpecificContents(T object, SerializerStream output) {
        serializeExtendedRequestName(object, output);
        serializeRequestExtendedSpecificContents(object, output);
    }

    protected abstract void serializeRequestExtendedSpecificContents(
            T object, SerializerStream output);
}
