/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpVersionMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpVersionMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpVersionMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpVersionMessageHandler extends SftpMessageHandler<SftpVersionMessage> {

    public SftpVersionMessageHandler(SshContext context) {
        super(context);
    }

    public SftpVersionMessageHandler(SshContext context, SftpVersionMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array) {
        return new SftpVersionMessageParser(array);
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array, int startPosition) {
        return new SftpVersionMessageParser(array, startPosition);
    }

    @Override
    public SftpVersionMessagePreparator getPreparator() {
        return new SftpVersionMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpVersionMessageSerializer getSerializer() {
        return new SftpVersionMessageSerializer(message);
    }
}
