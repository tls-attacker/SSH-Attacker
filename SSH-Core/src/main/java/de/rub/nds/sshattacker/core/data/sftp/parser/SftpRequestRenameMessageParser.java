/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRenameMessage;
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
        message.setNewPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("NewPath length: {}", message.getNewPathLength().getValue());
        message.setNewPath(
                parseByteString(message.getNewPathLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("NewPath: {}", () -> backslashEscapeString(message.getNewPath().getValue()));
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseNewPath();
    }
}
