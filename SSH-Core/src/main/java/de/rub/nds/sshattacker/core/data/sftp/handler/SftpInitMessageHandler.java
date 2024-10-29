/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpInitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpInitMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpInitMessageHandler extends SftpMessageHandler<SftpInitMessage> {

    public SftpInitMessageHandler(SshContext context) {
        super(context);
    }

    public SftpInitMessageHandler(SshContext context, SftpInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array) {
        return new SftpInitMessageParser(array);
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, int startPosition) {
        return new SftpInitMessageParser(array, startPosition);
    }

    @Override
    public SftpInitMessagePreparator getPreparator() {
        return new SftpInitMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpInitMessageSerializer getSerializer() {
        return new SftpInitMessageSerializer(message);
    }
}
