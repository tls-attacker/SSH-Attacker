/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseHandleMessageParser
        extends SftpResponseMessageParser<SftpResponseHandleMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseHandleMessageParser(byte[] array) {
        super(array);
    }

    public SftpResponseHandleMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpResponseHandleMessage createMessage() {
        return new SftpResponseHandleMessage();
    }

    private void parseHandle() {
        int handleLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setHandleLength(handleLength);
        LOGGER.debug("Handle length: {}", handleLength);
        byte[] handle = parseByteArrayField(handleLength);
        message.setHandle(handle);
        LOGGER.debug("Handle: {}", () -> ArrayConverter.bytesToRawHexString(handle));
    }

    @Override
    protected void parseResponseSpecificContents() {
        parseHandle();
    }
}
