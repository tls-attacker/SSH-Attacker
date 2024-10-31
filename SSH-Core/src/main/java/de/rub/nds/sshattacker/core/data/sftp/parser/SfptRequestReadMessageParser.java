/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestReadMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SfptRequestReadMessageParser
        extends SftpRequestWithHandleMessageParser<SfptRequestReadMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SfptRequestReadMessageParser(byte[] array) {
        super(array);
    }

    public SfptRequestReadMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SfptRequestReadMessage createMessage() {
        return new SfptRequestReadMessage();
    }

    private void parseOffset() {
        message.setOffset(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("Offset: {}", message.getOffset().getValue());
    }

    private void parseLength() {
        message.setLength(parseIntField(DataFormatConstants.UINT32_SIZE));
        LOGGER.debug("Length: {}", message.getLength().getValue());
    }

    @Override
    protected void parseRequestWithHandleSpecificContents() {
        parseOffset();
        parseLength();
    }
}
