/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHomeDirectoryMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestHomeDirectoryMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestHomeDirectoryMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestHomeDirectoryMessageSerializer(SftpRequestHomeDirectoryMessage message) {
        super(message);
    }

    private void serializeUsername() {
        Integer usernameLength = message.getUsernameLength().getValue();
        LOGGER.debug("Username length: {}", usernameLength);
        appendInt(usernameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String username = message.getUsername().getValue();
        LOGGER.debug("Username: {}", () -> backslashEscapeString(username));
        appendString(username, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeUsername();
    }
}
