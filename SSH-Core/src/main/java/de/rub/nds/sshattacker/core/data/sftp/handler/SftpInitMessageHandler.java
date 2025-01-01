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

    @Override
    public void adjustContext(SshContext context, SftpInitMessage object) {
        int receivedClientVersion = object.getVersion().getValue();
        context.setSftpClientVersion(receivedClientVersion);
        context.setSftpClientSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));

        // Set negotiated SFTP version based on own server version and received client version
        if (receivedClientVersion < context.getConfig().getSftpServerVersion()) {
            context.setSftpNegotiatedVersion(receivedClientVersion);
        } else {
            context.setSftpNegotiatedVersion(context.getConfig().getSftpServerVersion());
        }
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, SshContext context) {
        return new SftpInitMessageParser(array);
    }

    @Override
    public SftpInitMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpInitMessageParser(array, startPosition);
    }

    public static final SftpInitMessagePreparator PREPARATOR = new SftpInitMessagePreparator();

    public static final SftpInitMessageSerializer SERIALIZER = new SftpInitMessageSerializer();
}
