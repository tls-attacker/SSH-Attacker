/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestHardlinkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestHardlinkMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestHardlinkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeNewPath(
            SftpRequestHardlinkMessage object, SerializerStream output) {
        Integer newPathLength = object.getNewPathLength().getValue();
        LOGGER.debug("NewPath length: {}", newPathLength);
        output.appendInt(newPathLength);
        String newPath = object.getNewPath().getValue();
        LOGGER.debug("NewPath: {}", () -> backslashEscapeString(newPath));
        output.appendString(newPath, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents(
            SftpRequestHardlinkMessage object, SerializerStream output) {
        serializeNewPath(object, output);
    }
}
