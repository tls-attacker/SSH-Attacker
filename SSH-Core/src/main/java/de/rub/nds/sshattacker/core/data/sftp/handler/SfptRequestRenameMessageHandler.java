/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestRenameMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SfptRequestRenameMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SfptRequestRenameMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SfptRequestRenameMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SfptRequestRenameMessageHandler extends SftpMessageHandler<SfptRequestRenameMessage> {

    public SfptRequestRenameMessageHandler(SshContext context) {
        super(context);
    }

    public SfptRequestRenameMessageHandler(SshContext context, SfptRequestRenameMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SfptRequestRenameMessage
    }

    @Override
    public SfptRequestRenameMessageParser getParser(byte[] array) {
        return new SfptRequestRenameMessageParser(array);
    }

    @Override
    public SfptRequestRenameMessageParser getParser(byte[] array, int startPosition) {
        return new SfptRequestRenameMessageParser(array, startPosition);
    }

    @Override
    public SfptRequestRenameMessagePreparator getPreparator() {
        return new SfptRequestRenameMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SfptRequestRenameMessageSerializer getSerializer() {
        return new SfptRequestRenameMessageSerializer(message);
    }
}
