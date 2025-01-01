/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestStatMessage> {

    @Override
    public SftpRequestStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestStatMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestStatMessagePreparator PREPARATOR =
            new SftpRequestStatMessagePreparator();

    public static final SftpRequestStatMessageSerializer SERIALIZER =
            new SftpRequestStatMessageSerializer();
}
