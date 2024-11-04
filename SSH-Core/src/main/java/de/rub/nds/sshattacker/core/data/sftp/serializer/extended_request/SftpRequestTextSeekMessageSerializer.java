/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestTextSeekMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestTextSeekMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestTextSeekMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestTextSeekMessageSerializer(SftpRequestTextSeekMessage message) {
        super(message);
    }

    private void serializeLineNumber() {
        Long lineNumber = message.getLineNumber().getValue();
        LOGGER.debug("LineNumber: {}", lineNumber);
        appendLong(lineNumber, DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents() {
        serializeLineNumber();
    }
}
