/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHomeDirectoryMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestHomeDirectoryMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestHomeDirectoryMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeUsername(
            SftpRequestHomeDirectoryMessage object, SerializerStream output) {
        Integer usernameLength = object.getUsernameLength().getValue();
        LOGGER.debug("Username length: {}", usernameLength);
        output.appendInt(usernameLength);
        String username = object.getUsername().getValue();
        LOGGER.debug("Username: {}", () -> backslashEscapeString(username));
        output.appendString(username, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents(
            SftpRequestHomeDirectoryMessage object, SerializerStream output) {
        serializeUsername(object, output);
    }
}
