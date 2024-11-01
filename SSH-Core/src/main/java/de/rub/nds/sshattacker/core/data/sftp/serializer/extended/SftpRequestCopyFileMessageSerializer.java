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
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestCopyFileMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyFileMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestCopyFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestCopyFileMessageSerializer(SftpRequestCopyFileMessage message) {
        super(message);
    }

    private void serializeDestinationPath() {
        LOGGER.debug("DestinationPath length: {}", message.getDestinationPathLength().getValue());
        appendInt(
                message.getDestinationPathLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "DestinationPath: {}",
                () -> backslashEscapeString(message.getDestinationPath().getValue()));
        appendString(message.getDestinationPath().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeOverwriteDestination() {
        LOGGER.debug(
                "OverwriteDestination: {}",
                Converter.byteToBoolean(message.getOverwriteDestination().getValue()));
        appendByte(message.getOverwriteDestination().getValue());
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents() {
        serializeDestinationPath();
        serializeOverwriteDestination();
    }
}
