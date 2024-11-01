/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestExtendedWithHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedWithHandleMessageParser<
                T extends SftpRequestExtendedWithHandleMessage<T>>
        extends SftpRequestExtendedMessageParser<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedWithHandleMessageParser(byte[] array) {
        super(array);
    }

    protected SftpRequestExtendedWithHandleMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    private void parseHandle() {
        message.setHandleLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Handle length: {}", message.getHandleLength().getValue());
        message.setHandle(parseByteArrayField(message.getHandleLength().getValue()));
        LOGGER.debug(
                "Handle: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getHandle().getValue()));
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseHandle();
        parseRequestExtendedWithHandleSpecificContents();
    }

    protected abstract void parseRequestExtendedWithHandleSpecificContents();
}
