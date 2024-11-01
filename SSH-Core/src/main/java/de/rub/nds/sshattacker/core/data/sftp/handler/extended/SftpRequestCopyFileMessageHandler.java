/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestCopyFileMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestCopyFileMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestCopyFileMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestCopyFileMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCopyFileMessageHandler
        extends SftpMessageHandler<SftpRequestCopyFileMessage> {

    public SftpRequestCopyFileMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestCopyFileMessageHandler(
            SshContext context, SftpRequestCopyFileMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestCopyFileMessage
    }

    @Override
    public SftpRequestCopyFileMessageParser getParser(byte[] array) {
        return new SftpRequestCopyFileMessageParser(array);
    }

    @Override
    public SftpRequestCopyFileMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestCopyFileMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestCopyFileMessagePreparator getPreparator() {
        return new SftpRequestCopyFileMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestCopyFileMessageSerializer getSerializer() {
        return new SftpRequestCopyFileMessageSerializer(message);
    }
}
