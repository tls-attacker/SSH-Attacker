/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestReadMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestReadMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestReadMessageSerializer(SftpRequestReadMessage message) {
        super(message);
    }

    private void serializeOffset() {
        LOGGER.debug("Offset: {}", message.getOffset().getValue());
        appendLong(message.getOffset().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    private void serializeLength() {
        LOGGER.debug("Length: {}", message.getLength().getValue());
        appendInt(message.getLength().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents() {
        serializeOffset();
        serializeLength();
    }
}
