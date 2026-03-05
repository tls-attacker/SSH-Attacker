/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestWithHandleMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileStatMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4RequestFileStatMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpV4RequestFileStatMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeFlags(
            SftpV4RequestFileStatMessage object, SerializerStream output) {
        Integer flags = object.getFlags().getValue();
        LOGGER.debug("Flags: {}", flags);
        output.appendInt(flags);
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpV4RequestFileStatMessage object, SerializerStream output) {
        serializeFlags(object, output);
    }
}
