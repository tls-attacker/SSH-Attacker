/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestLinkSetStatMessage;

public class SftpRequestLinkSetStatMessageSerializer
        extends SftpRequestExtendedWithPathMessageSerializer<SftpRequestLinkSetStatMessage> {

    public SftpRequestLinkSetStatMessageSerializer(SftpRequestLinkSetStatMessage message) {
        super(message);
    }

    private void serializeAttributes() {
        appendBytes(message.getAttributes().getHandler(null).getSerializer().serialize());
    }

    @Override
    protected void serializeRequestExtendedWithPathSpecificContents() {
        serializeAttributes();
    }
}
