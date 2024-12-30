/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestExtendedWithHandleMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestExtendedWithHandleMessageSerializer<
                T extends SftpRequestExtendedWithHandleMessage<T>>
        extends SftpRequestExtendedMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeHandle(T object, SerializerStream output) {
        Integer handleLength = object.getHandleLength().getValue();
        LOGGER.debug("Handle length: {}", handleLength);
        output.appendInt(handleLength);
        byte[] handle = object.getHandle().getValue();
        LOGGER.debug("Handle: {}", () -> ArrayConverter.bytesToRawHexString(handle));
        output.appendBytes(handle);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents(T object, SerializerStream output) {
        serializeHandle(object, output);
        serializeRequestExtendedWithHandleSpecificContents(object, output);
    }

    protected abstract void serializeRequestExtendedWithHandleSpecificContents(
            T object, SerializerStream output);
}
