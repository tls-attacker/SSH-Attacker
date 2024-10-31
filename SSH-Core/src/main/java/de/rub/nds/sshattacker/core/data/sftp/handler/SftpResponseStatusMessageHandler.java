/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpResponseStatusMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpResponseStatusMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpResponseStatusMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpResponseStatusMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseStatusMessageHandler
        extends SftpMessageHandler<SftpResponseStatusMessage> {

    public SftpResponseStatusMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseStatusMessageHandler(SshContext context, SftpResponseStatusMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpResponseStatusMessage
    }

    @Override
    public SftpResponseStatusMessageParser getParser(byte[] array) {
        return new SftpResponseStatusMessageParser(array);
    }

    @Override
    public SftpResponseStatusMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseStatusMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseStatusMessagePreparator getPreparator() {
        return new SftpResponseStatusMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseStatusMessageSerializer getSerializer() {
        return new SftpResponseStatusMessageSerializer(message);
    }
}
