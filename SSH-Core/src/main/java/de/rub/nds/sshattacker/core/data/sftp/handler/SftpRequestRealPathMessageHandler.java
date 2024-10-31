/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRealPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestRealPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestRealPathMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestRealPathMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRealPathMessageHandler
        extends SftpMessageHandler<SftpRequestRealPathMessage> {

    public SftpRequestRealPathMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRealPathMessageHandler(
            SshContext context, SftpRequestRealPathMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestRealPathMessage
    }

    @Override
    public SftpRequestRealPathMessageParser getParser(byte[] array) {
        return new SftpRequestRealPathMessageParser(array);
    }

    @Override
    public SftpRequestRealPathMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRealPathMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestRealPathMessagePreparator getPreparator() {
        return new SftpRequestRealPathMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestRealPathMessageSerializer getSerializer() {
        return new SftpRequestRealPathMessageSerializer(message);
    }
}
