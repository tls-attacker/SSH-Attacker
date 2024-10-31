/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpResponseMessageParser<T extends SftpResponseMessage<T>>
        extends SftpMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpResponseMessageParser(byte[] array) {
        super(array);
    }

    protected SftpResponseMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseRequestId() {
        message.setRequestId(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("RequestId: {}", message.getRequestId().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseRequestId();
        parseResponseSpecificContents();
    }

    protected abstract void parseResponseSpecificContents();
}
