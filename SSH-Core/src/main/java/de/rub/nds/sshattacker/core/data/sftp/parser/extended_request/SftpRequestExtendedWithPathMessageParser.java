/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExtendedWithPathMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedWithPathMessageParser<
                T extends SftpRequestExtendedWithPathMessage<T>>
        extends SftpRequestExtendedMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedWithPathMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestExtendedWithPathMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parsePath() {
        int pathLength = parseIntField();
        message.setPathLength(pathLength);
        LOGGER.debug("Path length: {}", pathLength);
        String path = parseByteString(pathLength, StandardCharsets.UTF_8);
        message.setPath(path);
        LOGGER.debug("Path: {}", () -> backslashEscapeString(path));
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parsePath();
        parseRequestExtendedWithPathSpecificContents();
    }

    protected abstract void parseRequestExtendedWithPathSpecificContents();
}
