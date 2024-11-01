/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestLimitsMessage;

public class SftpRequestLimitsMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestLimitsMessage> {

    public SftpRequestLimitsMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestLimitsMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestLimitsMessage createMessage() {
        return new SftpRequestLimitsMessage();
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {}
}
