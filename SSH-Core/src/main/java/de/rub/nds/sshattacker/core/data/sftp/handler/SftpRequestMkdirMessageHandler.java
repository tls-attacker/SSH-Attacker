/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestMkdirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestMkdirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestMkdirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestMkdirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestMkdirMessageHandler extends SftpMessageHandler<SftpRequestMkdirMessage> {

    public SftpRequestMkdirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestMkdirMessageHandler(SshContext context, SftpRequestMkdirMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestMkdirMessage
    }

    @Override
    public SftpRequestMkdirMessageParser getParser(byte[] array) {
        return new SftpRequestMkdirMessageParser(array);
    }

    @Override
    public SftpRequestMkdirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestMkdirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestMkdirMessagePreparator getPreparator() {
        return new SftpRequestMkdirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestMkdirMessageSerializer getSerializer() {
        return new SftpRequestMkdirMessageSerializer(message);
    }
}
