/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpResponseNameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpResponseNameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpResponseNameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseNameMessageHandler extends SftpMessageHandler<SftpResponseNameMessage> {

    public SftpResponseNameMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseNameMessageHandler(SshContext context, SftpResponseNameMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpResponseNameMessage
    }

    @Override
    public SftpResponseNameMessageParser getParser(byte[] array) {
        return new SftpResponseNameMessageParser(array);
    }

    @Override
    public SftpResponseNameMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseNameMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseNameMessagePreparator getPreparator() {
        return new SftpResponseNameMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseNameMessageSerializer getSerializer() {
        return new SftpResponseNameMessageSerializer(message);
    }
}
