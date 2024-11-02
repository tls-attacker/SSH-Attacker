/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestUnknownMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestUnknownMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestUnknownMessageSerializer(SftpRequestUnknownMessage message) {
        super(message);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        byte[] requestSpecificData = message.getRequestSpecificData().getValue();
        LOGGER.debug(
                "RequestSpecificData: {}",
                () -> ArrayConverter.bytesToRawHexString(requestSpecificData));
        appendBytes(requestSpecificData);
    }
}
