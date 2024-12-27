/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestRenameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestRenameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestRenameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestRenameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRenameMessageHandler
        extends SftpRequestMessageHandler<SftpRequestRenameMessage> {

    public SftpRequestRenameMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRenameMessageHandler(SshContext context, SftpRequestRenameMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestRenameMessageParser getParser(byte[] array) {
        return new SftpRequestRenameMessageParser(array);
    }

    @Override
    public SftpRequestRenameMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRenameMessageParser(array, startPosition);
    }

    public static final SftpRequestRenameMessagePreparator PREPARATOR =
            new SftpRequestRenameMessagePreparator();

    public static final SftpRequestRenameMessageSerializer SERIALIZER =
            new SftpRequestRenameMessageSerializer();
}
