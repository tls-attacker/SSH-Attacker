/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestReadDirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestReadDirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestReadDirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestReadDirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestReadDirMessageHandler
        extends SftpMessageHandler<SftpRequestReadDirMessage> {

    public SftpRequestReadDirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestReadDirMessageHandler(SshContext context, SftpRequestReadDirMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestReadDirMessage
    }

    @Override
    public SftpRequestReadDirMessageParser getParser(byte[] array) {
        return new SftpRequestReadDirMessageParser(array);
    }

    @Override
    public SftpRequestReadDirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestReadDirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestReadDirMessagePreparator getPreparator() {
        return new SftpRequestReadDirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestReadDirMessageSerializer getSerializer() {
        return new SftpRequestReadDirMessageSerializer(message);
    }
}
