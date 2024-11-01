/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestGetTempFolderMessage;

public class SftpRequestGetTempFolderMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestGetTempFolderMessage> {

    public SftpRequestGetTempFolderMessageSerializer(SftpRequestGetTempFolderMessage message) {
        super(message);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {}
}
