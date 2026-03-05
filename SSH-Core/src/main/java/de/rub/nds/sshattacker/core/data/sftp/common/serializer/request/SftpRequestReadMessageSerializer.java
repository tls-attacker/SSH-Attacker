/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestReadMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestReadMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeOffset(SftpRequestReadMessage object, SerializerStream output) {
        Long offset = object.getOffset().getValue();
        LOGGER.debug("Offset: {}", offset);
        output.appendLong(offset);
    }

    private static void serializeLength(SftpRequestReadMessage object, SerializerStream output) {
        Integer length = object.getLength().getValue();
        LOGGER.debug("Length: {}", length);
        output.appendInt(length);
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpRequestReadMessage object, SerializerStream output) {
        serializeOffset(object, output);
        serializeLength(object, output);
    }
}
