/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.serializer.request.SftpRequestWithHandleMessageSerializer;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.request.SftpV4RequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpV4RequestFileSetStatMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpV4RequestFileSetStatMessage> {

    private static void serializeAttributes(
            SftpV4RequestFileSetStatMessage object, SerializerStream output) {
        output.appendBytes(object.getAttributes().serialize());
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpV4RequestFileSetStatMessage object, SerializerStream output) {
        serializeAttributes(object, output);
    }
}
