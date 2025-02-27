/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpUnknownMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpUnknownMessageSerializer extends SftpMessageSerializer<SftpUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeMessageSpecificContents(
            SftpUnknownMessage object, SerializerStream output) {
        byte[] payload = object.getPayload().getValue();
        LOGGER.debug("Payload: {}", () -> ArrayConverter.bytesToHexString(payload));
        output.appendBytes(payload);
    }
}
