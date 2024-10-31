/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestReadMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SfptRequestReadMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SfptRequestReadMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SfptRequestReadMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SfptRequestReadMessageHandler extends SftpMessageHandler<SfptRequestReadMessage> {

    public SfptRequestReadMessageHandler(SshContext context) {
        super(context);
    }

    public SfptRequestReadMessageHandler(SshContext context, SfptRequestReadMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SfptRequestReadMessage
    }

    @Override
    public SfptRequestReadMessageParser getParser(byte[] array) {
        return new SfptRequestReadMessageParser(array);
    }

    @Override
    public SfptRequestReadMessageParser getParser(byte[] array, int startPosition) {
        return new SfptRequestReadMessageParser(array, startPosition);
    }

    @Override
    public SfptRequestReadMessagePreparator getPreparator() {
        return new SfptRequestReadMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SfptRequestReadMessageSerializer getSerializer() {
        return new SfptRequestReadMessageSerializer(message);
    }
}
