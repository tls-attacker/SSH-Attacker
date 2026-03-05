/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestFileStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestFileStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request.SftpRequestFileStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestFileStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatVfsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileStatVfsMessage> {

    @Override
    public SftpRequestFileStatVfsMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestFileStatVfsMessageParser(array);
    }

    @Override
    public SftpRequestFileStatVfsMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestFileStatVfsMessageParser(array, startPosition);
    }

    public static final SftpRequestFileStatVfsMessagePreparator PREPARATOR =
            new SftpRequestFileStatVfsMessagePreparator();

    public static final SftpRequestFileStatVfsMessageSerializer SERIALIZER =
            new SftpRequestFileStatVfsMessageSerializer();
}
