/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestRmdirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestRmdirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestRmdirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestRmdirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRmdirMessageHandler extends SftpMessageHandler<SftpRequestRmdirMessage> {

    public SftpRequestRmdirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRmdirMessageHandler(SshContext context, SftpRequestRmdirMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestRmdirMessage
    }

    @Override
    public SftpRequestRmdirMessageParser getParser(byte[] array) {
        return new SftpRequestRmdirMessageParser(array);
    }

    @Override
    public SftpRequestRmdirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRmdirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestRmdirMessagePreparator getPreparator() {
        return new SftpRequestRmdirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestRmdirMessageSerializer getSerializer() {
        return new SftpRequestRmdirMessageSerializer(message);
    }
}
