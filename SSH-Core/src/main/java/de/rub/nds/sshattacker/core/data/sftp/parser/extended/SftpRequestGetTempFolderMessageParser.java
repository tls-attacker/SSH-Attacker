/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestGetTempFolderMessage;

public class SftpRequestGetTempFolderMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestGetTempFolderMessage> {

    public SftpRequestGetTempFolderMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestGetTempFolderMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestGetTempFolderMessage createMessage() {
        return new SftpRequestGetTempFolderMessage();
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {}
}
