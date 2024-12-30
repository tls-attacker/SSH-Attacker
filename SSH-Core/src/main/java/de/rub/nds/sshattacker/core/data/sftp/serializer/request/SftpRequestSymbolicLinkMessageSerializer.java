/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSymbolicLinkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestSymbolicLinkMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestSymbolicLinkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeTargetPath(
            SftpRequestSymbolicLinkMessage object, SerializerStream output) {
        Integer targetPathLength = object.getTargetPathLength().getValue();
        LOGGER.debug("TargetPath length: {}", targetPathLength);
        output.appendInt(targetPathLength);
        String targetPath = object.getTargetPath().getValue();
        LOGGER.debug("TargetPath: {}", () -> backslashEscapeString(targetPath));
        output.appendString(targetPath, StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestWithPathSpecificContents(
            SftpRequestSymbolicLinkMessage object, SerializerStream output) {
        serializeTargetPath(object, output);
    }
}
