/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestExtendedWithPathMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedWithPathMessageSerializer<
                T extends SftpRequestExtendedWithPathMessage<T>>
        extends SftpRequestExtendedMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedWithPathMessageSerializer(T message) {
        super(message);
    }

    private void serializePath() {
        LOGGER.debug("Path length: {}", message.getPathLength().getValue());
        appendInt(message.getPathLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Path: {}", () -> backslashEscapeString(message.getPath().getValue()));
        appendString(message.getPath().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializePath();
        serializeRequestExtendedWithPathSpecificContents();
    }

    protected abstract void serializeRequestExtendedWithPathSpecificContents();
}
