/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestSpaceAvailableMessage;

public class SftpRequestSpaceAvailableMessageParser
        extends SftpRequestExtendedWithPathMessageParser<SftpRequestSpaceAvailableMessage> {

    public SftpRequestSpaceAvailableMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestSpaceAvailableMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestSpaceAvailableMessage createMessage() {
        return new SftpRequestSpaceAvailableMessage();
    }

    @Override
    protected void parseRequestExtendedWithPathSpecificContents() {}
}
