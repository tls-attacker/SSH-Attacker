/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestWithPathMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestSetStatMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpV4RequestSetStatMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpV4RequestSetStatMessage> {

    private static void serializeAttributes(
            SftpV4RequestSetStatMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithPathSpecificContents(
            SftpV4RequestSetStatMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
