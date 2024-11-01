/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestExpandPathMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestExpandPathMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestExpandPathMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestExpandPathMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestExpandPathMessageHandler
        extends SftpMessageHandler<SftpRequestExpandPathMessage> {

    public SftpRequestExpandPathMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestExpandPathMessageHandler(
            SshContext context, SftpRequestExpandPathMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestExpandPathMessage
    }

    @Override
    public SftpRequestExpandPathMessageParser getParser(byte[] array) {
        return new SftpRequestExpandPathMessageParser(array);
    }

    @Override
    public SftpRequestExpandPathMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestExpandPathMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestExpandPathMessagePreparator getPreparator() {
        return new SftpRequestExpandPathMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestExpandPathMessageSerializer getSerializer() {
        return new SftpRequestExpandPathMessageSerializer(message);
    }
}
