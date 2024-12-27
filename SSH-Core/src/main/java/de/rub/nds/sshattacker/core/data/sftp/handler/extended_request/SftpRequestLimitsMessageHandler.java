/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_request;

import de.rub.nds.sshattacker.core.data.sftp.handler.request.SftpRequestMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_request.SftpRequestLimitsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request.SftpRequestLimitsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request.SftpRequestLimitsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLimitsMessageHandler
        extends SftpRequestMessageHandler<SftpRequestLimitsMessage> {

    public SftpRequestLimitsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestLimitsMessageHandler(SshContext context, SftpRequestLimitsMessage message) {
        super(context, message);
    }

    @Override
    public SftpRequestLimitsMessageParser getParser(byte[] array) {
        return new SftpRequestLimitsMessageParser(array);
    }

    @Override
    public SftpRequestLimitsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestLimitsMessageParser(array, startPosition);
    }

    public static final SftpRequestLimitsMessagePreparator PREPARATOR =
            new SftpRequestLimitsMessagePreparator();

    @Override
    public SftpRequestLimitsMessageSerializer getSerializer() {
        return new SftpRequestLimitsMessageSerializer(message);
    }
}
