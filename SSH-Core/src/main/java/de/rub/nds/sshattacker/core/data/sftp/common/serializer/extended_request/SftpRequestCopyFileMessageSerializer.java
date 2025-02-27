/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestCopyFileMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestCopyFileMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestCopyFileMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeDestinationPath(
            SftpRequestCopyFileMessage object, SerializerStream output) {
        Integer destinationPathLength = object.getDestinationPathLength().getValue();
        LOGGER.debug("DestinationPath length: {}", destinationPathLength);
        output.appendInt(destinationPathLength);
        String destinationPath = object.getDestinationPath().getValue();
        LOGGER.debug("DestinationPath: {}", () -> backslashEscapeString(destinationPath));
        output.appendString(destinationPath, StandardCharsets.UTF_8);
    }

    private static void serializeOverwriteDestination(
            SftpRequestCopyFileMessage object, SerializerStream output) {
        Byte overwriteDestination = object.getOverwriteDestination().getValue();
        LOGGER.debug(
                "OverwriteDestination: {}", () -> Converter.byteToBoolean(overwriteDestination));
        output.appendByte(overwriteDestination);
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents(
            SftpRequestCopyFileMessage object, SerializerStream output) {
        serializeDestinationPath(object, output);
        serializeOverwriteDestination(object, output);
    }
}
