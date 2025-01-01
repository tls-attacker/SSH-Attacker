/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestOpenMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestOpenMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestOpenMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestOpenMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestOpenMessageHandler
        extends SftpRequestMessageHandler<SftpRequestOpenMessage> {

    @Override
    public SftpRequestOpenMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestOpenMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestOpenMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestOpenMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestOpenMessagePreparator PREPARATOR =
            new SftpRequestOpenMessagePreparator();

    public static final SftpRequestOpenMessageSerializer SERIALIZER =
            new SftpRequestOpenMessageSerializer();
}
