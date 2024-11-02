/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWithHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithHandleMessageParser<T extends SftpRequestWithHandleMessage<T>>
        extends SftpRequestMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestWithHandleMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestWithHandleMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
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
    protected void parseRequestSpecificContents() {
        parseHandle();
        parseRequestWithHandleSpecificContents();
    }

    protected abstract void parseRequestWithHandleSpecificContents();
}
