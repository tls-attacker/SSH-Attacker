/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.response;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseNameMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4ResponseNameMessageSerializer
        extends SftpResponseMessageSerializer<SftpV4ResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeNameEntries(
            SftpV4ResponseNameMessage object, SerializerStream output) {
        Integer countNameEntries = object.getNameEntriesCount().getValue();
        LOGGER.debug("CountNameEntries: {}", countNameEntries);
        output.appendInt(countNameEntries);

        object.getNameEntries().forEach(nameEntry -> output.appendBytes(nameEntry.serialize()));
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpV4ResponseNameMessage object, SerializerStream output) {
        serializeNameEntries(object, output);
    }
}
