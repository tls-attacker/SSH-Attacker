/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestOpenMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestOpenMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestOpenMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestOpenMessageHandler extends SftpMessageHandler<SftpRequestOpenMessage> {

    public SftpRequestOpenMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestOpenMessageHandler(SshContext context, SftpRequestOpenMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestOpenMessage
    }

    @Override
    public SftpRequestOpenMessageParser getParser(byte[] array) {
        return new SftpRequestOpenMessageParser(array);
    }

    @Override
    public SftpRequestOpenMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestOpenMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestOpenMessagePreparator getPreparator() {
        return new SftpRequestOpenMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestOpenMessageSerializer getSerializer() {
        return new SftpRequestOpenMessageSerializer(message);
    }
}
