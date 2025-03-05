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
import de.rub.nds.sshattacker.core.protocol.common.MessageSentHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpVersionMessageHandler extends SftpMessageHandler<SftpVersionMessage>
        implements MessageSentHandler<SftpVersionMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, SftpVersionMessage object) {
        context.setSftpServerVersion(object.getVersion().getValue());
        context.setSftpServerSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));

        if (context.isClient()) {
            negotiateSftpVersion(context);
        }
    }

    @Override
    public void adjustContextAfterMessageSent(SshContext context, SftpVersionMessage object) {
        if (context.isServer()) {
            context.setSftpServerVersion(object.getVersion().getValue());
            negotiateSftpVersion(context);
        }
    }

    private static void negotiateSftpVersion(SshContext context) {
        // Set negotiated SFTP version based on own server version and received client version
        Integer sftpClientVersion = context.getChooser().getSftpClientVersion();
        Integer sftpServerVersion = context.getChooser().getSftpServerVersion();
        int negotiatedVersion = sftpServerVersion;
        if (sftpClientVersion < sftpServerVersion) {
            negotiatedVersion = sftpClientVersion;
        }
        context.setSftpNegotiatedVersion(negotiatedVersion);
        LOGGER.info(
                "Negotiated SFTP version {}. Client version: {}. Server Version: {}",
                negotiatedVersion,
                sftpClientVersion,
                sftpServerVersion);
        if (negotiatedVersion < 3 || negotiatedVersion > 4) {
            LOGGER.debug("Negotiated SFTP version {} is not implemented.", negotiatedVersion);
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
