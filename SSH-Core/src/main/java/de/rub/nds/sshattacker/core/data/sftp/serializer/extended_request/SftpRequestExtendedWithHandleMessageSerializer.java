/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExtendedWithHandleMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedWithHandleMessageSerializer<
                T extends SftpRequestExtendedWithHandleMessage<T>>
        extends SftpRequestExtendedMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpRequestExtendedWithHandleMessageSerializer(T message) {
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
    protected void serializeRequestExtendedSpecificContents() {
        serializeHandle();
        serializeRequestExtendedWithHandleSpecificContents();
    }

    protected abstract void serializeRequestExtendedWithHandleSpecificContents();
}
