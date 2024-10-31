/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestFileStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestFileStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestFileStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestFileStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileStatMessageHandler
        extends SftpMessageHandler<SftpRequestFileStatMessage> {

    public SftpRequestFileStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestFileStatMessageHandler(
            SshContext context, SftpRequestFileStatMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestFileStatMessage
    }

    @Override
    public SftpRequestFileStatMessageParser getParser(byte[] array) {
        return new SftpRequestFileStatMessageParser(array);
    }

    @Override
    public SftpRequestFileStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestFileStatMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestFileStatMessagePreparator getPreparator() {
        return new SftpRequestFileStatMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestFileStatMessageSerializer getSerializer() {
        return new SftpRequestFileStatMessageSerializer(message);
    }
}
