/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpResponseHandleMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpResponseHandleMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpResponseHandleMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseHandleMessageHandler
        extends SftpMessageHandler<SftpResponseHandleMessage> {

    public SftpResponseHandleMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseHandleMessageHandler(SshContext context, SftpResponseHandleMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpResponseHandleMessage
    }

    @Override
    public SftpResponseHandleMessageParser getParser(byte[] array) {
        return new SftpResponseHandleMessageParser(array);
    }

    @Override
    public SftpResponseHandleMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseHandleMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseHandleMessagePreparator getPreparator() {
        return new SftpResponseHandleMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseHandleMessageSerializer getSerializer() {
        return new SftpResponseHandleMessageSerializer(message);
    }
}
