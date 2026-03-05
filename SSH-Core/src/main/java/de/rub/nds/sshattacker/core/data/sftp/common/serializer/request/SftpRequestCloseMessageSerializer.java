/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestCloseMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;

public class SftpRequestCloseMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestCloseMessage> {

    @Override
    protected void serializeRequestWithHandleSpecificContents(
            SftpRequestCloseMessage object, SerializerStream output) {}
}
