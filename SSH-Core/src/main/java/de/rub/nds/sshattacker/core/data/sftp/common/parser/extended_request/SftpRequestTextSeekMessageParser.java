/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestTextSeekMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestTextSeekMessageParser
        extends SftpRequestExtendedWithHandleMessageParser<SftpRequestTextSeekMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestTextSeekMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestTextSeekMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestTextSeekMessage createMessage() {
        return new SftpRequestTextSeekMessage();
    }

    private void parseLineNumber() {
        long lineNumber = parseLongField();
        message.setLineNumber(lineNumber);
        LOGGER.debug("LineNumber: {}", lineNumber);
    }

    @Override
    protected void parseRequestExtendedWithHandleSpecificContents() {
        parseLineNumber();
    }
}
