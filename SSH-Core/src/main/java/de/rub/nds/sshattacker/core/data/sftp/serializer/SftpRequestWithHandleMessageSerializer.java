/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestWithHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithHandleMessageSerializer<
                T extends SftpRequestWithHandleMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestWithHandleMessageSerializer(T message) {
        super(message);
    }

    public void serializeHandle() {
        LOGGER.debug("Handle length: {}", message.getHandleLength().getValue());
        appendInt(message.getHandleLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "Handle: {}",
                () -> ArrayConverter.bytesToRawHexString(message.getHandle().getValue()));
        appendBytes(message.getHandle().getValue());
    }

    public void serializeRequestSpecificContents() {
        serializeHandle();
        serializeRequestWithHandleSpecificContents();
    }

    protected abstract void serializeRequestWithHandleSpecificContents();
}
