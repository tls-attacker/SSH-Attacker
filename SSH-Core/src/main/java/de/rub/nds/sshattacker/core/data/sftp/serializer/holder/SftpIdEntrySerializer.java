/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.holder;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpIdEntrySerializer extends Serializer<SftpIdEntry> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SftpIdEntry idEntry;

    public SftpIdEntrySerializer(SftpIdEntry idEntry) {
        super();
        this.idEntry = idEntry;
    }

    private void serializeId() {
        Integer id = idEntry.getId().getValue();
        LOGGER.debug("Id: {}", id);
        appendInt(id, DataFormatConstants.UINT32_SIZE);
    }

    @Override
    protected final void serializeBytes() {
        serializeId();
    }
}
