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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class SftpHandshakeMessageSerializer<T extends SftpHandshakeMessage<T>>
        extends SftpMessageSerializer<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    private void serializeVersion(T object, SerializerStream output) {
        Integer version = object.getVersion().getValue();
        LOGGER.debug("Version: {}", version);
        output.appendInt(version, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeExtensions(T object, SerializerStream output) {
        object.getExtensions().forEach(extension -> output.appendBytes(extension.serialize()));
    }

    protected void serializeMessageSpecificContents(T object, SerializerStream output) {
        serializeVersion(object, output);
        serializeExtensions(object, output);
    }
}
