/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestReadMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestReadMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestReadMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestReadMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadMessageHandler extends SftpMessageHandler<SftpRequestReadMessage> {

    public SftpRequestReadMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestReadMessageHandler(SshContext context, SftpRequestReadMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestReadMessage
    }

    @Override
    public SftpRequestReadMessageParser getParser(byte[] array) {
        return new SftpRequestReadMessageParser(array);
    }

    @Override
    public SftpRequestReadMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestReadMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestReadMessagePreparator getPreparator() {
        return new SftpRequestReadMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestReadMessageSerializer getSerializer() {
        return new SftpRequestReadMessageSerializer(message);
    }
}
