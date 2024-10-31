/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRenameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestRenameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestRenameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestRenameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRenameMessageHandler extends SftpMessageHandler<SftpRequestRenameMessage> {

    public SftpRequestRenameMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRenameMessageHandler(SshContext context, SftpRequestRenameMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestRenameMessage
    }

    @Override
    public SftpRequestRenameMessageParser getParser(byte[] array) {
        return new SftpRequestRenameMessageParser(array);
    }

    @Override
    public SftpRequestRenameMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRenameMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestRenameMessagePreparator getPreparator() {
        return new SftpRequestRenameMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestRenameMessageSerializer getSerializer() {
        return new SftpRequestRenameMessageSerializer(message);
    }
}
