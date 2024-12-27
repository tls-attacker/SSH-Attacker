/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.response;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeNameEntries(
            SftpResponseNameMessage object, SerializerStream output) {
        Integer countNameEntries = object.getNameEntriesCount().getValue();
        LOGGER.debug("CountNameEntries: {}", countNameEntries);
        output.appendInt(countNameEntries, DataFormatConstants.UINT32_SIZE);

        object.getNameEntries().forEach(nameEntry -> output.appendBytes(nameEntry.serialize()));
    }

    @Override
    protected void serializeResponseSpecificContents(
            SftpResponseNameMessage object, SerializerStream output) {
        serializeNameEntries(object, output);
    }
}
