/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRemoveMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestRemoveMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestRemoveMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestRemoveMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveMessageHandler extends SftpMessageHandler<SftpRequestRemoveMessage> {

    public SftpRequestRemoveMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRemoveMessageHandler(SshContext context, SftpRequestRemoveMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestRemoveMessage
    }

    @Override
    public SftpRequestRemoveMessageParser getParser(byte[] array) {
        return new SftpRequestRemoveMessageParser(array);
    }

    @Override
    public SftpRequestRemoveMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRemoveMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestRemoveMessagePreparator getPreparator() {
        return new SftpRequestRemoveMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestRemoveMessageSerializer getSerializer() {
        return new SftpRequestRemoveMessageSerializer(message);
    }
}
