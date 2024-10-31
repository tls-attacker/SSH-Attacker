/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestWriteMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestWriteMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestWriteMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestWriteMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestWriteMessageHandler extends SftpMessageHandler<SftpRequestWriteMessage> {

    public SftpRequestWriteMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestWriteMessageHandler(SshContext context, SftpRequestWriteMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestWriteMessage
    }

    @Override
    public SftpRequestWriteMessageParser getParser(byte[] array) {
        return new SftpRequestWriteMessageParser(array);
    }

    @Override
    public SftpRequestWriteMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestWriteMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestWriteMessagePreparator getPreparator() {
        return new SftpRequestWriteMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestWriteMessageSerializer getSerializer() {
        return new SftpRequestWriteMessageSerializer(message);
    }
}
