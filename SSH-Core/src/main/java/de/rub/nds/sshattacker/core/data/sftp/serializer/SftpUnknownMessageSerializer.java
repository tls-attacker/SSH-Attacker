/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpUnknownMessageSerializer extends SftpMessageSerializer<SftpUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpUnknownMessageSerializer(SftpUnknownMessage message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {
        LOGGER.debug("Payload: {}", ArrayConverter.bytesToHexString(message.getPayload()));
        appendBytes(message.getPayload().getValue());
    }
}
