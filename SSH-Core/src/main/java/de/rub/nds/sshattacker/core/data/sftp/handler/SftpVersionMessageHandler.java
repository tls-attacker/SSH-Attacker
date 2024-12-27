/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpVersionMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpVersionMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpVersionMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpVersionMessageHandler extends SftpMessageHandler<SftpVersionMessage> {

    public SftpVersionMessageHandler(SshContext context) {
        super(context);
    }

    public SftpVersionMessageHandler(SshContext context, SftpVersionMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        int receivedServerVersion = message.getVersion().getValue();
        context.setSftpServerVersion(receivedServerVersion);
        context.setSftpServerSupportedExtensions(message.getExtensions());
        message.getExtensions().forEach(extension -> extension.getHandler(context).adjustContext());

        // Set negotiated SFTP version based on own client version and received server version
        if (receivedServerVersion < context.getConfig().getSftpClientVersion()) {
            context.setSftpNegotiatedVersion(receivedServerVersion);
        } else {
            context.setSftpNegotiatedVersion(context.getConfig().getSftpClientVersion());
        }
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array) {
        return new SftpVersionMessageParser(array);
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array, int startPosition) {
        return new SftpVersionMessageParser(array, startPosition);
    }

    public static final SftpVersionMessagePreparator PREPARATOR =
            new SftpVersionMessagePreparator();

    public static final SftpVersionMessageSerializer SERIALIZER =
            new SftpVersionMessageSerializer();
}
