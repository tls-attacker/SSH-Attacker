/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestWithHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestWithHandleMessageSerializer<
                T extends SftpRequestWithHandleMessage<T>>
        extends SftpRequestMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestWithHandleMessageSerializer(T message) {
        super(message);
    }

    private void serializeHandle() {
        Integer handleLength = message.getHandleLength().getValue();
        LOGGER.debug("Handle length: {}", handleLength);
        appendInt(handleLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] handle = message.getHandle().getValue();
        LOGGER.debug("Handle: {}", () -> ArrayConverter.bytesToRawHexString(handle));
        appendBytes(handle);
    }

    @Override
    protected void serializeRequestSpecificContents() {
        serializeHandle();
        serializeRequestWithHandleSpecificContents();
    }

    protected abstract void serializeRequestWithHandleSpecificContents();
}
