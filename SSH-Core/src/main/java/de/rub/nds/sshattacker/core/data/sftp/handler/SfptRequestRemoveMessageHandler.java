/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestRemoveMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SfptRequestRemoveMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SfptRequestRemoveMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SfptRequestRemoveMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SfptRequestRemoveMessageHandler extends SftpMessageHandler<SfptRequestRemoveMessage> {

    public SfptRequestRemoveMessageHandler(SshContext context) {
        super(context);
    }

    public SfptRequestRemoveMessageHandler(SshContext context, SfptRequestRemoveMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SfptRequestRemoveMessage
    }

    @Override
    public SfptRequestRemoveMessageParser getParser(byte[] array) {
        return new SfptRequestRemoveMessageParser(array);
    }

    @Override
    public SfptRequestRemoveMessageParser getParser(byte[] array, int startPosition) {
        return new SfptRequestRemoveMessageParser(array, startPosition);
    }

    @Override
    public SfptRequestRemoveMessagePreparator getPreparator() {
        return new SfptRequestRemoveMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SfptRequestRemoveMessageSerializer getSerializer() {
        return new SfptRequestRemoveMessageSerializer(message);
    }
}
