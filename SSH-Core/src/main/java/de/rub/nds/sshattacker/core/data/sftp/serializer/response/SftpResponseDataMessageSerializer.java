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
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseDataMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseDataMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseDataMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeData(SftpResponseDataMessage object, SerializerStream output) {
        Integer dataLength = object.getDataLength().getValue();
        LOGGER.debug("Data length: {}", dataLength);
        output.appendInt(dataLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] data = object.getData().getValue();
        LOGGER.debug("Data: {}", () -> ArrayConverter.bytesToRawHexString(data));
        output.appendBytes(data);
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseDataMessage object, SerializerStream output) {
        serializeData(object, output);
    }
}
