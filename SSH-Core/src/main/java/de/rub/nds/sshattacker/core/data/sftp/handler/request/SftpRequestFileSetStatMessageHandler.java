/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.request;

import de.rub.nds.sshattacker.core.data.sftp.message.request.SftpRequestFileSetStatMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.request.SftpRequestFileSetStatMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.request.SftpRequestFileSetStatMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.request.SftpRequestFileSetStatMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestFileSetStatMessageHandler
        extends SftpRequestMessageHandler<SftpRequestFileSetStatMessage> {

    public SftpRequestFileSetStatMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestFileSetStatMessageHandler(
            SshContext context, SftpRequestFileSetStatMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestFileSetStatMessageParser getParser(byte[] array) {
        return new SftpRequestFileSetStatMessageParser(array, context.getChooser());
    }

    @Override
    public SftpRequestFileSetStatMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestFileSetStatMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpRequestFileSetStatMessagePreparator PREPARATOR =
            new SftpRequestFileSetStatMessagePreparator();

    public static final SftpRequestFileSetStatMessageSerializer SERIALIZER =
            new SftpRequestFileSetStatMessageSerializer();
}
