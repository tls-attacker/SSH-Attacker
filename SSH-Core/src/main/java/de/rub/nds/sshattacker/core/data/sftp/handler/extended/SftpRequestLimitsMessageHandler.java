/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended.SftpRequestLimitsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended.SftpRequestLimitsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended.SftpRequestLimitsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpRequestLimitsMessageHandler extends SftpMessageHandler<SftpRequestLimitsMessage> {

    public SftpRequestLimitsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpRequestLimitsMessageHandler(SshContext context, SftpRequestLimitsMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpRequestLimitsMessage
    }

    @Override
    public SftpRequestLimitsMessageParser getParser(byte[] array) {
        return new SftpRequestLimitsMessageParser(array);
    }

    @Override
    public SftpRequestLimitsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpRequestLimitsMessageParser(array, startPosition);
    }

    @Override
    public SftpRequestLimitsMessagePreparator getPreparator() {
        return new SftpRequestLimitsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpRequestLimitsMessageSerializer getSerializer() {
        return new SftpRequestLimitsMessageSerializer(message);
    }
}
