/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestCloseMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestCloseMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestCloseMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestCloseMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestCloseMessageHandler extends SftpMessageHandler<SftpRequestCloseMessage> {

    public SftpRequestCloseMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestCloseMessageHandler(SshContext context, SftpRequestCloseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestCloseMessage
    }

    @Override
    public SftpRequestCloseMessageParser getParser(byte[] array) {
        return new SftpRequestCloseMessageParser(array);
    }

    @Override
    public SftpRequestCloseMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestCloseMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestCloseMessagePreparator getPreparator() {
        return new SftpRequestCloseMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestCloseMessageSerializer getSerializer() {
        return new SftpRequestCloseMessageSerializer(message);
    }
}
