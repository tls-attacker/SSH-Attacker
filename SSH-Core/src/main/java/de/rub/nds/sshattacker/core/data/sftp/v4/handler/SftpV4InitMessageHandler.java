/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler;

import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.SftpV4InitMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.SftpV4InitMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preperator.SftpV4InitMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.SftpV4InitMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpV4InitMessageHandler extends SftpMessageHandler<SftpV4InitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, SftpV4InitMessage object) {
        int receivedClientVersion = object.getVersion().getValue();
        context.setSftpClientVersion(receivedClientVersion);
        context.setSftpClientSupportedExtensions(object.getExtensions());
        object.getExtensions().forEach(extension -> extension.adjustContext(context));

        // Set negotiated SFTP version based on own server version and received client version
        int negotiatedVersion;
        if (receivedClientVersion < context.getConfig().getSftpServerVersion()) {
            negotiatedVersion = receivedClientVersion;
        } else {
            negotiatedVersion = context.getConfig().getSftpServerVersion();
        }
        context.setSftpNegotiatedVersion(negotiatedVersion);
        if (negotiatedVersion < 3 || negotiatedVersion > 4) {
            LOGGER.warn("Negotiated SFTP version {} is not implemented.", negotiatedVersion);
        }
    }

    @Override
    public SftpV4InitMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4InitMessageParser(array);
    }

    @Override
    public SftpV4InitMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpV4InitMessageParser(array, startPosition);
    }

    public static final SftpV4InitMessagePreparator PREPARATOR = new SftpV4InitMessagePreparator();

    public static final SftpV4InitMessageSerializer SERIALIZER = new SftpV4InitMessageSerializer();
}
