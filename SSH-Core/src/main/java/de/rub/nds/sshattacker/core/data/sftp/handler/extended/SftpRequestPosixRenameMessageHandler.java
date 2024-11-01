/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestPosixRenameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestPosixRenameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestPosixRenameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestPosixRenameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestPosixRenameMessageHandler
        extends SftpMessageHandler<SftpRequestPosixRenameMessage> {

    public SftpRequestPosixRenameMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestPosixRenameMessageHandler(
            SshContext context, SftpRequestPosixRenameMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestPosixRenameMessage
    }

    @Override
    public SftpRequestPosixRenameMessageParser getParser(byte[] array) {
        return new SftpRequestPosixRenameMessageParser(array);
    }

    @Override
    public SftpRequestPosixRenameMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestPosixRenameMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestPosixRenameMessagePreparator getPreparator() {
        return new SftpRequestPosixRenameMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestPosixRenameMessageSerializer getSerializer() {
        return new SftpRequestPosixRenameMessageSerializer(message);
    }
}
