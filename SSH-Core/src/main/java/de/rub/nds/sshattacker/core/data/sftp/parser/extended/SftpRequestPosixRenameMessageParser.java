/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestPosixRenameMessage;
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
        message.setNewPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("NewPath length: {}", message.getNewPathLength().getValue());
        message.setNewPath(
                parseByteString(message.getNewPathLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("NewPath: {}", () -> backslashEscapeString(message.getNewPath().getValue()));
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {
        parseNewPath();
    }
}
