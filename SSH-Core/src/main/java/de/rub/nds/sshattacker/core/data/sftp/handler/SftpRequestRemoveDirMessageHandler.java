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
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestRemoveDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestRemoveDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestRemoveDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestRemoveDirMessageHandler
        extends SftpMessageHandler<SftpRequestRmdirMessage> {

    public SftpRequestRemoveDirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestRemoveDirMessageHandler(SshContext context, SftpRequestRmdirMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestRmdirMessage
    }

    @Override
    public SftpRequestRemoveDirMessageParser getParser(byte[] array) {
        return new SftpRequestRemoveDirMessageParser(array);
    }

    @Override
    public SftpRequestRemoveDirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestRemoveDirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestRemoveDirMessagePreparator getPreparator() {
        return new SftpRequestRemoveDirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestRemoveDirMessageSerializer getSerializer() {
        return new SftpRequestRemoveDirMessageSerializer(message);
    }
}
