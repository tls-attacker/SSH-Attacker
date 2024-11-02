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
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestCopyFileMessage;
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
        Integer destinationPathLength = message.getDestinationPathLength().getValue();
        LOGGER.debug("DestinationPath length: {}", destinationPathLength);
        appendInt(destinationPathLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String destinationPath = message.getDestinationPath().getValue();
        LOGGER.debug("DestinationPath: {}", () -> backslashEscapeString(destinationPath));
        appendString(destinationPath, StandardCharsets.UTF_8);
    }

    private void serializeOverwriteDestination() {
        Byte overwriteDestination = message.getOverwriteDestination().getValue();
        LOGGER.debug(
                "OverwriteDestination: {}", () -> Converter.byteToBoolean(overwriteDestination));
        appendByte(overwriteDestination);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents() {
        serializeDestinationPath();
        serializeOverwriteDestination();
    }
}
