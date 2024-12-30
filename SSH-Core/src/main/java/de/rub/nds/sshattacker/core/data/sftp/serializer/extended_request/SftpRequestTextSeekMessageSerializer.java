/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestTextSeekMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestTextSeekMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestTextSeekMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeLineNumber(
            SftpRequestTextSeekMessage object, SerializerStream output) {
        Long lineNumber = object.getLineNumber().getValue();
        LOGGER.debug("LineNumber: {}", lineNumber);
        output.appendLong(lineNumber);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents(
            SftpRequestTextSeekMessage object, SerializerStream output) {
        serializeLineNumber(object, output);
    }
}
