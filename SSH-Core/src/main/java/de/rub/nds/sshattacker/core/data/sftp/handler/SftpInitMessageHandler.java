/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpInitMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpInitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpInitMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpInitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpInitMessageHandler extends SftpMessageHandler<SftpInitMessage> {

    public SftpInitMessageHandler(SshContext context) {
        super(context);
    }

    public SftpInitMessageHandler(SshContext context, SftpInitMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        int receivedClientVersion = message.getVersion().getValue();
        context.setSftpClientVersion(receivedClientVersion);
        context.setSftpClientSupportedExtensions(message.getExtensions());
        message.getExtensions().forEach(extension -> extension.getHandler(context).adjustContext());

        // Set negotiated SFTP version based on own server version and received client version
        if (receivedClientVersion < context.getConfig().getSftpServerVersion()) {
            context.setSftpNegotiatedVersion(receivedClientVersion);
        } else {
            context.setSftpNegotiatedVersion(context.getConfig().getSftpServerVersion());
        }
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array) {
        return new SftpInitMessageParser(array);
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, int startPosition) {
        return new SftpInitMessageParser(array, startPosition);
    }

    public static final SftpInitMessagePreparator PREPARATOR = new SftpInitMessagePreparator();

    public static final SftpInitMessageSerializer SERIALIZER = new SftpInitMessageSerializer();
}
