/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.data.sftp.SftpMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.SftpUnknownMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.SftpUnknownMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.SftpUnknownMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.SftpUnknownMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpUnknownMessageHandler extends SftpMessageHandler<SftpUnknownMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public void adjustContext(SshContext context, SftpUnknownMessage object) {
        LOGGER.debug(
                "Received unknown message:\n{}",
                () -> ArrayConverter.bytesToHexString(object.getPayload()));
    }

    @Override
    public SftpUnknownMessageParser getParser(byte[] array, SshContext context) {
        return new SftpUnknownMessageParser(array);
    }

    @Override
    public SftpUnknownMessageParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpUnknownMessageParser(array, startPosition);
    }

    public static final SftpUnknownMessagePreparator PREPARATOR =
            new SftpUnknownMessagePreparator();

    public static final SftpUnknownMessageSerializer SERIALIZER =
            new SftpUnknownMessageSerializer();
}
