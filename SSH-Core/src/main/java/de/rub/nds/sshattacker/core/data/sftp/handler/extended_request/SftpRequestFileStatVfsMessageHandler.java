/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestFileStatVfsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestFileStatVfsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestFileStatVfsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestFileStatVfsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatVfsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileStatVfsMessage> {

    public SftpRequestFileStatVfsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestFileStatVfsMessageHandler(
            SshContext context, SftpRequestFileStatVfsMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestFileStatVfsMessageParser getParser(byte[] array) {
        return new SftpRequestFileStatVfsMessageParser(array);
    }

    @Override
    public SftpRequestFileStatVfsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestFileStatVfsMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestFileStatVfsMessagePreparator getPreparator() {
        return new SftpRequestFileStatVfsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestFileStatVfsMessageSerializer getSerializer() {
        return new SftpRequestFileStatVfsMessageSerializer(message);
    }
}
