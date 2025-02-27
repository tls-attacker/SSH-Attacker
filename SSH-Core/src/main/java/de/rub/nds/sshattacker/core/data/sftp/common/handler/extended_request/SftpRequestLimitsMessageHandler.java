/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.extended_request.SftpRequestLimitsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.extended_request.SftpRequestLimitsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.extended_request.SftpRequestLimitsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLimitsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestLimitsMessage> {

    @Override
    public SftpRequestLimitsMessageParser getParser(byte[] array, SshContext context) {
        return new SftpRequestLimitsMessageParser(array);
    }

    @Override
    public SftpRequestLimitsMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpRequestLimitsMessageParser(array, startPosition);
    }

    public static final SftpRequestLimitsMessagePreparator PREPARATOR =
            new SftpRequestLimitsMessagePreparator();

    public static final SftpRequestLimitsMessageSerializer SERIALIZER =
            new SftpRequestLimitsMessageSerializer();
}
