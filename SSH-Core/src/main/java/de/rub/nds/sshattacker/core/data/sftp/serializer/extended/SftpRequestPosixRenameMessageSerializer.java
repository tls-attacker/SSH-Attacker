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
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestPosixRenameMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestPosixRenameMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestPosixRenameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestPosixRenameMessageSerializer(SftpRequestPosixRenameMessage message) {
        super(message);
    }

    private void serializeNewPath() {
        LOGGER.debug("NewPath length: {}", message.getNewPathLength().getValue());
        appendInt(message.getNewPathLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("NewPath: {}", () -> backslashEscapeString(message.getNewPath().getValue()));
        appendString(message.getNewPath().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents() {
        serializeNewPath();
    }
}
