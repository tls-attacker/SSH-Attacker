/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.response;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseHandleMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseHandleMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeHandle(SftpResponseHandleMessage object, SerializerStream output) {
        Integer handleLength = object.getHandleLength().getValue();
        LOGGER.debug("Handle length: {}", handleLength);
        output.appendInt(handleLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] handle = object.getHandle().getValue();
        LOGGER.debug("Handle: {}", () -> ArrayConverter.bytesToRawHexString(handle));
        output.appendBytes(handle);
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseHandleMessage object, SerializerStream output) {
        serializeHandle(object, output);
    }
}
