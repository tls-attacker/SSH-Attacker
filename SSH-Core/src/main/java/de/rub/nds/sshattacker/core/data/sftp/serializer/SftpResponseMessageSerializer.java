/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpResponseMessageSerializer<T extends SftpResponseMessage<T>>
        extends SftpMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpResponseMessageSerializer(T message) {
        super(message);
    }

    private void serializeRequestId() {
        LOGGER.debug("RequestId: {}", message.getRequestId().getValue());
        appendInt(message.getRequestId().getValue(), DataFormatConstants.UINT32_SIZE);
    }

    public void serializeMessageSpecificContents() {
        serializeRequestId();
        serializeResponseSpecificContents();
    }

    protected abstract void serializeResponseSpecificContents();
}
