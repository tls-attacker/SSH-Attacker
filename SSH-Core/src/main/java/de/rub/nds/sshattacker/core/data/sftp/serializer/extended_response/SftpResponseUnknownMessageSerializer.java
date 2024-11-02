/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseMessageSerializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUnknownMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseUnknownMessageSerializer(SftpResponseUnknownMessage message) {
        super(message);
    }

    @Override
    protected void serializeResponseSpecificContents() {
        byte[] responseSpecificData = message.getResponseSpecificData().getValue();
        LOGGER.debug(
                "ResponseSpecificData: {}",
                () -> ArrayConverter.bytesToRawHexString(responseSpecificData));
        appendBytes(responseSpecificData);
    }
}
