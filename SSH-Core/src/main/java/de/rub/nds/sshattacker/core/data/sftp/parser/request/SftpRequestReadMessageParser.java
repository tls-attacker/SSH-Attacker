/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestReadMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestReadMessageParser
        extends SftpRequestWithHandleMessageParser<SftpRequestReadMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestReadMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestReadMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestReadMessage createMessage() {
        return new SftpRequestReadMessage();
    }

    private void parseOffset() {
        long offset = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setOffset(offset);
        LOGGER.debug("Offset: {}", offset);
    }

    private void parseLength() {
        int length = parseIntField(DataFormatConstants.UINT32_SIZE);
        message.setLength(length);
        LOGGER.debug("Length: {}", length);
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseOffset();
        parseLength();
    }
}
