/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestOpenMessageSerializer(SftpRequestOpenMessage message) {
        super(message);
    }

    private void serializePFlags() {
        Integer pFlags = message.getPFlags().getValue();
        LOGGER.debug("PFlags: {}", pFlags);
        appendInt(pFlags, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeAttributes() {
        appendBytes(message.getAttributes().getHandler(null).getSerializer().serialize());
    }

    @Override
    protected void serializeRequestWithPathSpecificContents() {
        serializePFlags();
        serializeAttributes();
    }
}
