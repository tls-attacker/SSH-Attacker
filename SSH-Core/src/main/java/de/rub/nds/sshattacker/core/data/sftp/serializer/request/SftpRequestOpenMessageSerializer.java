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
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestOpenMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePFlags(SftpRequestOpenMessage object, SerializerStream output) {
        Integer pFlags = object.getPFlags().getValue();
        LOGGER.debug("PFlags: {}", pFlags);
        output.appendInt(pFlags, DataFormatConstants.UINT32_SIZE);
    }

    private static void serializeAttributes(
            SftpRequestOpenMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithPathSpecificContents(
            SftpRequestOpenMessage object, SerializerStream output) {
        serializePFlags(object, output);
        serializeAttributes(object, output);
    }
}
