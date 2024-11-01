/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestHomeDirectoryMessage;
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
        LOGGER.debug("Username length: {}", message.getUsernameLength().getValue());
        appendInt(message.getUsernameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Username: {}", () -> backslashEscapeString(message.getUsername().getValue()));
        appendString(message.getUsername().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeUsername();
    }
}
