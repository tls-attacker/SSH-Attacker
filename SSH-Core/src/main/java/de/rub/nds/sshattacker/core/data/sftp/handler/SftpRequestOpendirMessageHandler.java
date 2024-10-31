/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpRequestOpendirMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpRequestOpendirMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpRequestOpendirMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpRequestOpendirMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestOpendirMessageHandler
        extends SftpMessageHandler<SftpRequestOpendirMessage> {

    public SftpRequestOpendirMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestOpendirMessageHandler(SshContext context, SftpRequestOpendirMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestOpendirMessage
    }

    @Override
    public SftpRequestOpendirMessageParser getParser(byte[] array) {
        return new SftpRequestOpendirMessageParser(array);
    }

    @Override
    public SftpRequestOpendirMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestOpendirMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestOpendirMessagePreparator getPreparator() {
        return new SftpRequestOpendirMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestOpendirMessageSerializer getSerializer() {
        return new SftpRequestOpendirMessageSerializer(message);
    }
}
