/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestMessageParser<T extends SftpRequestMessage<T>>
        extends SftpMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseRequestId() {
        int requestId = parseIntField();
        message.setRequestId(requestId);
        LOGGER.debug("RequestId: {}", requestId);
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseRequestId();
        parseRequestSpecificContents();
    }

    protected abstract void parseRequestSpecificContents();
}
