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
import de.rub.nds.sshattacker.core.data.sftp.message.SftpHandshakeMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpHandshakeMessageSerializer<T extends SftpHandshakeMessage<T>>
        extends SftpMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected SftpHandshakeMessageSerializer(T message) {
        super(message);
    }

    private void serializeVersion() {
        Integer version = message.getVersion().getValue();
        LOGGER.debug("Version: {}", version);
        appendInt(version, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeExtensions() {
        message.getExtensions()
                .forEach(
                        extension ->
                                appendBytes(
                                        extension.getHandler(null).getSerializer().serialize()));
    }

    protected void serializeMessageSpecificContents() {
        serializeVersion();
        serializeExtensions();
    }
}
