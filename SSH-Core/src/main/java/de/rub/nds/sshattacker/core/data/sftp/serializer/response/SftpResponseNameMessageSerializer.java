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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpResponseNameMessageSerializer
        extends SftpResponseMessageSerializer<SftpResponseNameMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpResponseNameMessageSerializer(SftpResponseNameMessage message) {
        super(message);
    }

    private void serializeNameEntries() {
        Integer countNameEntries = message.getNameEntriesCount().getValue();
        LOGGER.debug("CountNameEntries: {}", countNameEntries);
        appendInt(countNameEntries, DataFormatConstants.UINT32_SIZE);

        message.getNameEntries()
                .forEach(
                        nameEntry ->
                                appendBytes(
                                        nameEntry.getHandler(null).getSerializer().serialize()));
    }

    @Override
    protected void serializeResponseSpecificContents() {
        serializeNameEntries();
    }
}
