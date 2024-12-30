/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHomeDirectoryMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestHomeDirectoryMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestHomeDirectoryMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestHomeDirectoryMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestHomeDirectoryMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestHomeDirectoryMessage createMessage() {
        return new SftpRequestHomeDirectoryMessage();
    }

    private void parseUsername() {
        int usernameLength = parseIntField();
        message.setUsernameLength(usernameLength);
        LOGGER.debug("Username length: {}", usernameLength);
        String username = parseByteString(usernameLength, StandardCharsets.UTF_8);
        message.setUsername(username);
        LOGGER.debug("Username: {}", () -> backslashEscapeString(username));
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseUsername();
    }
}
