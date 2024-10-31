/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SfptRequestCloseMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SfptRequestCloseMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SfptRequestCloseMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SfptRequestCloseMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SfptRequestCloseMessageHandler extends SftpMessageHandler<SfptRequestCloseMessage> {

    public SfptRequestCloseMessageHandler(SshContext context) {
        super(context);
    }

    public SfptRequestCloseMessageHandler(SshContext context, SfptRequestCloseMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SfptRequestCloseMessage
    }

    @Override
    public SfptRequestCloseMessageParser getParser(byte[] array) {
        return new SfptRequestCloseMessageParser(array);
    }

    @Override
    public SfptRequestCloseMessageParser getParser(byte[] array, int startPosition) {
        return new SfptRequestCloseMessageParser(array, startPosition);
    }

    @Override
    public SfptRequestCloseMessagePreparator getPreparator() {
        return new SfptRequestCloseMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SfptRequestCloseMessageSerializer getSerializer() {
        return new SfptRequestCloseMessageSerializer(message);
    }
}
