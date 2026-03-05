/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatVfsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestStatVfsMessage> {

    @Override
    public SftpRequestStatVfsMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestStatVfsMessageParser(array);
    }

    @Override
    public SftpRequestStatVfsMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestStatVfsMessageParser(array, startPosition);
    }

    public static final SftpRequestStatVfsMessagePreparator PREPARATOR =
            new SftpRequestStatVfsMessagePreparator();

    public static final SftpRequestStatVfsMessageSerializer SERIALIZER =
            new SftpRequestStatVfsMessageSerializer();
}
