/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpRequestMessageSerializer<T extends SftpRequestMessage<T>>
        extends SftpMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeRequestId(T object, SerializerStream output) {
        Integer requestId = object.getRequestId().getValue();
        LOGGER.debug("RequestId: {}", requestId);
        output.appendInt(requestId);
    }

    @Override
    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeRequestId(object, output);
        serializeRequestSpecificContents(object, output);
    }

    protected abstract void serializeRequestSpecificContents(T object, SerializerStream output);
}
