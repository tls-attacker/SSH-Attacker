/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.SftpVersionMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.SftpVersionMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.SftpVersionMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.SftpVersionMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpVersionMessageHandler extends SftpMessageHandler<SftpVersionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, SftpVersionMessage object) {
        int receivedServerVersion = object.getVersion().getValue();
        context.setSftpServerVersion(receivedServerVersion);
        context.setSftpServerSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));

        // Set negotiated SFTP version based on own client version and received server version
        int negotiatedVersion;
        if (receivedServerVersion < context.getConfig().getSftpClientVersion()) {
            negotiatedVersion = receivedServerVersion;
        } else {
            negotiatedVersion = context.getConfig().getSftpClientVersion();
        }
        context.setSftpNegotiatedVersion(negotiatedVersion);
        if (negotiatedVersion < 3 || negotiatedVersion > 4) {
            LOGGER.warn("Negotiated SFTP version {} is not implemented.", negotiatedVersion);
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
