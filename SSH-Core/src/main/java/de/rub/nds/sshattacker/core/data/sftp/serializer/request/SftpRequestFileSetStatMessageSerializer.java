/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpRequestFileSetStatMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestFileSetStatMessage> {

    private static void serializeAttributes(
            SftpRequestFileSetStatMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpRequestFileSetStatMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
