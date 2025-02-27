/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestFileStatVfsMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpRequestFileStatVfsMessageSerializer
        extends SftpRequestExtendedWithHandleMessageSerializer<SftpRequestFileStatVfsMessage> {

    @Override
    protected void serializeRequestExtendedWithHandleSpecificContents(
            SftpRequestFileStatVfsMessage object, SerializerStream output) {}
}
