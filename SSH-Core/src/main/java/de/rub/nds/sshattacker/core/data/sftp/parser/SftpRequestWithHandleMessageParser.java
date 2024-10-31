/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestWithHandleMessage;
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
        message.setHandleLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Handle length: {}", message.getHandleLength().getValue());
        message.setHandle(parseByteArrayField(message.getHandleLength().getValue()));
        LOGGER.debug(
                "Handle: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getHandle().getValue()));
    }

    public void parseRequestSpecificContents() {
        parseHandle();
        parseRequestWithHandleSpecificContents();
    }

    protected abstract void parseRequestWithHandleSpecificContents();
}
