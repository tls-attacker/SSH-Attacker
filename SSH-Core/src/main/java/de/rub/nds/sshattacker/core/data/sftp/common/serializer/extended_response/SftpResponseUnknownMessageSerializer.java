/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_response.SftpResponseUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseUnknownMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseUnknownMessage object, SerializerStream output) {
        byte[] responseSpecificData = object.getResponseSpecificData().getValue();
        LOGGER.debug(
                "ResponseSpecificData: {}",
                () -> ArrayConverter.bytesToRawHexString(responseSpecificData));
        output.appendBytes(responseSpecificData);
    }
}
