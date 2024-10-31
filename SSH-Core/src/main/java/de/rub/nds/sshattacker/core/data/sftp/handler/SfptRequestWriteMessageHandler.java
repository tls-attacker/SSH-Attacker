/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestWriteMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SfptRequestWriteMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SfptRequestWriteMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SfptRequestWriteMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SfptRequestWriteMessageHandler extends SftpMessageHandler<SfptRequestWriteMessage> {

    public SfptRequestWriteMessageHandler(SshContext context) {
        super(context);
    }

    public SfptRequestWriteMessageHandler(SshContext context, SfptRequestWriteMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SfptRequestWriteMessage
    }

    @Override
    public SfptRequestWriteMessageParser getParser(byte[] array) {
        return new SfptRequestWriteMessageParser(array);
    }

    @Override
    public SfptRequestWriteMessageParser getParser(byte[] array, int startPosition) {
        return new SfptRequestWriteMessageParser(array, startPosition);
    }

    @Override
    public SfptRequestWriteMessagePreparator getPreparator() {
        return new SfptRequestWriteMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SfptRequestWriteMessageSerializer getSerializer() {
        return new SfptRequestWriteMessageSerializer(message);
    }
}
