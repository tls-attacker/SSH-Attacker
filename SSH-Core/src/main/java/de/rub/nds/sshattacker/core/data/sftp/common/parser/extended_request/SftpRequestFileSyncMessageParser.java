/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestFileSyncMessage;

public class SftpRequestFileSyncMessageParser
        extends SftpRequestExtendedWithHandleMessageParser<SftpRequestFileSyncMessage> {

    public SftpRequestFileSyncMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestFileSyncMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestFileSyncMessage createMessage() {
        return new SftpRequestFileSyncMessage();
    }

    @Override
    protected void parseRequestExtendedWithHandleSpecificContents() {}
}
