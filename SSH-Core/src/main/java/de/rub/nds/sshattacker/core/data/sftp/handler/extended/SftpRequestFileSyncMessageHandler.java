/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestFileSyncMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestFileSyncMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestFileSyncMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestFileSyncMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileSyncMessageHandler
        extends SftpMessageHandler<SftpRequestFileSyncMessage> {

    public SftpRequestFileSyncMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestFileSyncMessageHandler(
            SshContext context, SftpRequestFileSyncMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestFileSyncMessage
    }

    @Override
    public SftpRequestFileSyncMessageParser getParser(byte[] array) {
        return new SftpRequestFileSyncMessageParser(array);
    }

    @Override
    public SftpRequestFileSyncMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestFileSyncMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestFileSyncMessagePreparator getPreparator() {
        return new SftpRequestFileSyncMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestFileSyncMessageSerializer getSerializer() {
        return new SftpRequestFileSyncMessageSerializer(message);
    }
}
