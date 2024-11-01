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
        message.setPathLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Path length: {}", message.getPathLength().getValue());
        message.setPath(
                parseByteString(message.getPathLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug("Path: {}", () -> backslashEscapeString(message.getPath().getValue()));
    }

    @Override
    protected void parseRequestSpecificContents() {
        parsePath();
        parseRequestWithPathSpecificContents();
    }

    protected abstract void parseRequestWithPathSpecificContents();
}
