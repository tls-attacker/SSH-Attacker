/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestPosixRenameMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestPosixRenameMessageParser
        extends SftpRequestExtendedWithPathMessageParser<SftpRequestPosixRenameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestPosixRenameMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestPosixRenameMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestPosixRenameMessage createMessage() {
        return new SftpRequestPosixRenameMessage();
    }

    private void parseNewPath() {
        int newPathLength = parseIntField();
        message.setNewPathLength(newPathLength);
        LOGGER.debug("NewPath length: {}", newPathLength);
        String newPath = parseByteString(newPathLength, StandardCharsets.UTF_8);
        message.setNewPath(newPath);
        LOGGER.debug("NewPath: {}", () -> backslashEscapeString(newPath));
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseNewPath();
    }
}
