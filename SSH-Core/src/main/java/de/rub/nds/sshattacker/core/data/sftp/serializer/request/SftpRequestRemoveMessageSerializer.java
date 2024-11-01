/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRemoveMessage;

public class SftpRequestRemoveMessageSerializer
        extends SftpRequestWithPathMessageSerializer<SftpRequestRemoveMessage> {

    public SftpRequestRemoveMessageSerializer(SftpRequestRemoveMessage message) {
        super(message);
    }

    @Override
    protected void serializeRequestWithPathSpecificContents() {}
}
