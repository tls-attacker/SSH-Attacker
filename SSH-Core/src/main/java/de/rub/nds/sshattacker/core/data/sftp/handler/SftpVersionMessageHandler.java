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

    @Override
    public void adjustContext(SshContext context, SftpVersionMessage object) {
        int receivedServerVersion = object.getVersion().getValue();
        context.setSftpServerVersion(receivedServerVersion);
        context.setSftpServerSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));

        // Set negotiated SFTP version based on own client version and received server version
        if (receivedServerVersion < context.getConfig().getSftpClientVersion()) {
            context.setSftpNegotiatedVersion(receivedServerVersion);
        } else {
            context.setSftpNegotiatedVersion(context.getConfig().getSftpClientVersion());
        }
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array, SshContext context) {
        return new SftpVersionMessageParser(array);
    }

    @Override
    public SftpVersionMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpVersionMessageParser(array, startPosition);
    }

    public static final SftpVersionMessagePreparator PREPARATOR =
            new SftpVersionMessagePreparator();

    public static final SftpVersionMessageSerializer SERIALIZER =
            new SftpVersionMessageSerializer();
}
