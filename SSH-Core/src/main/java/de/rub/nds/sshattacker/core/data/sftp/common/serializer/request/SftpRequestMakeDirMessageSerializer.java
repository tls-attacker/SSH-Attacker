/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestMakeDirMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpRequestMakeDirMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestMakeDirMessage> {

    private static void serializeAttributes(
            SftpRequestMakeDirMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithPathSpecificContents(
            SftpRequestMakeDirMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
