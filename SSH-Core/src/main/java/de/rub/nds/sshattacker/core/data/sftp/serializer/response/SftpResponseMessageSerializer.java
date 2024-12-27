/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpResponseMessageSerializer<T extends SftpResponseMessage<T>>
        extends SftpMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeRequestId(T object, SerializerStream output) {
        Integer requestId = object.getRequestId().getValue();
        LOGGER.debug("RequestId: {}", requestId);
        output.appendInt(requestId, DataFormatConstants.UINT32_SIZE);
    }

    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeRequestId(object, output);
        serializeResponseSpecificContents(object, output);
    }

    protected abstract void serializeResponseSpecificContents(T object, SerializerStream output);
}
