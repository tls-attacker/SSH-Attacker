/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestRenameMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestRenameMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestRenameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestRenameMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestRenameMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestRenameMessage createMessage() {
        return new SftpRequestRenameMessage();
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
    protected void parseRequestWithPathSpecificContents() {
        parseNewPath();
    }
}
