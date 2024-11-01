/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSymbolicLinkMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestSymbolicLinkMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestSymbolicLinkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestSymbolicLinkMessageSerializer(SftpRequestSymbolicLinkMessage message) {
        super(message);
    }

    private void serializeTargetPath() {
        LOGGER.debug("TargetPath length: {}", message.getTargetPathLength().getValue());
        appendInt(message.getTargetPathLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "TargetPath: {}", () -> backslashEscapeString(message.getTargetPath().getValue()));
        appendString(message.getTargetPath().getValue(), StandardCharsets.UTF_8);
    }

    @Override
    protected void serializeRequestWithPathSpecificContents() {
        serializeTargetPath();
    }
}
