/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestSetStatMessage> {

    @Override
    public SftpRequestSetStatMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestSetStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestSetStatMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestSetStatMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestSetStatMessagePreparator PREPARATOR =
            new SftpRequestSetStatMessagePreparator();

    public static final SftpRequestSetStatMessageSerializer SERIALIZER =
            new SftpRequestSetStatMessageSerializer();
}
