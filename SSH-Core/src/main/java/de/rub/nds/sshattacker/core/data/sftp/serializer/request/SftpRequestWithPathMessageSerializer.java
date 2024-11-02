/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWithPathMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithPathMessageSerializer<T extends SftpRequestWithPathMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestWithPathMessageSerializer(T message) {
        super(message);
    }

    private void serializePath() {
        Integer pathLength = message.getPathLength().getValue();
        LOGGER.debug("Path length: {}", pathLength);
        appendInt(pathLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String path = message.getPath().getValue();
        LOGGER.debug("Path: {}", () -> backslashEscapeString(path));
        appendString(path, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestSpecificContents() {
        serializePath();
        serializeRequestWithPathSpecificContents();
    }

    protected abstract void serializeRequestWithPathSpecificContents();
}
