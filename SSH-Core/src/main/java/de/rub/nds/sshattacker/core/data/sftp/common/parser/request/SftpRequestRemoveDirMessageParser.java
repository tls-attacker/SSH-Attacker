/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.request.SftpRequestRemoveDirMessage;

public class SftpRequestRemoveDirMessageParser
        extends SftpRequestWithPathMessageParser<SftpRequestRemoveDirMessage> {

    public SftpRequestRemoveDirMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestRemoveDirMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public SftpRequestRemoveDirMessage createMessage() {
        return new SftpRequestRemoveDirMessage();
    }

    @Override
    protected void parseRequestWithPathSpecificContents() {}
}
