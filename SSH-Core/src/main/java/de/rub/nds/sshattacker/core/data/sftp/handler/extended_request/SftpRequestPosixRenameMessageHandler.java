/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestPosixRenameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestPosixRenameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestPosixRenameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestPosixRenameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestPosixRenameMessageHandler
        extends SftpRequestMessageHandler<SftpRequestPosixRenameMessage> {

    @Override
    public SftpRequestPosixRenameMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestPosixRenameMessageParser(array);
    }

    @Override
    public SftpRequestPosixRenameMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestPosixRenameMessageParser(array, startPosition);
    }

    public static final SftpRequestPosixRenameMessagePreparator PREPARATOR =
            new SftpRequestPosixRenameMessagePreparator();

    public static final SftpRequestPosixRenameMessageSerializer SERIALIZER =
            new SftpRequestPosixRenameMessageSerializer();
}
