/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestWithPathMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithPathMessageSerializer<T extends SftpRequestWithPathMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializePath(T object, SerializerStream output) {
        Integer pathLength = object.getPathLength().getValue();
        LOGGER.debug("Path length: {}", pathLength);
        output.appendInt(pathLength);
        String path = object.getPath().getValue();
        LOGGER.debug("Path: {}", () -> backslashEscapeString(path));
        output.appendString(path, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestSpecificContents(T object, SerializerStream output) {
        serializePath(object, output);
        serializeRequestWithPathSpecificContents(object, output);
    }

    protected abstract void serializeRequestWithPathSpecificContents(
            T object, SerializerStream output);
}
