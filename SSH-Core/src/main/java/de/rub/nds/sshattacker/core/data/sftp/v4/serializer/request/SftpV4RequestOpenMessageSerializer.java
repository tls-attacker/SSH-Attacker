/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestWithPathMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestOpenMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4RequestOpenMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpV4RequestOpenMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeOpenFlags(
            SftpV4RequestOpenMessage object, SerializerStream output) {
        Integer openFlags = object.getOpenFlags().getValue();
        LOGGER.debug("OpenFlags: {}", openFlags);
        output.appendInt(openFlags);
    }

    private static void serializeAttributes(
            SftpV4RequestOpenMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithPathSpecificContents(
            SftpV4RequestOpenMessage object, SerializerStream output) {
        serializeOpenFlags(object, output);
        serializeAttributes(object, output);
    }
}
