/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestSymbolicLinkMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestSymbolicLinkMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestSymbolicLinkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestSymbolicLinkMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestSymbolicLinkMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestSymbolicLinkMessage createMessage() {
        return new SftpRequestSymbolicLinkMessage();
    }

    private void parseTargetPath() {
        int targetPathLength = parseIntField();
        message.setTargetPathLength(targetPathLength);
        LOGGER.debug("TargetPath length: {}", targetPathLength);
        String targetPath = parseByteString(targetPathLength, StandardCharsets.UTF_8);
        message.setTargetPath(targetPath);
        LOGGER.debug("TargetPath: {}", () -> backslashEscapeString(targetPath));
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {
        parseTargetPath();
    }
}
