/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWithPathMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithPathMessageParser<T extends SftpRequestWithPathMessage<T>>
        extends SftpRequestMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestWithPathMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestWithPathMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parsePath() {
        int pathLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setPathLength(pathLength);
        LOGGER.debug("Path length: {}", pathLength);
        String path = parseByteString(pathLength, StandardCharsets.UTF_8);
        message.setPath(path);
        LOGGER.debug("Path: {}", () -> backslashEscapeString(path));
    }

    @Override
    protected void parseRequestSpecificContents() {
        parsePath();
        parseRequestWithPathSpecificContents();
    }

    protected abstract void parseRequestWithPathSpecificContents();
}
