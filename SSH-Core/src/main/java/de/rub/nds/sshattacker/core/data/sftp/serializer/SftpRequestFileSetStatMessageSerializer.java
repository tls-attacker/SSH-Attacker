/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer;

import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestFileSetStatMessage;

public class SftpRequestFileSetStatMessageSerializer
        extends SftpRequestWithHandleMessageSerializer<SftpRequestFileSetStatMessage> {

    public SftpRequestFileSetStatMessageSerializer(SftpRequestFileSetStatMessage message) {
        super(message);
    }

    private void serializeAttributes() {
        appendBytes(message.getAttributes().getHandler(null).getSerializer().serialize());
    }

    @Override
    protected void serializeRequestWithHandleSpecificContents() {
        serializeAttributes();
    }
}
