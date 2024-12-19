/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.extended_response;

import de.rub.nds.sshattacker.core.data.sftp.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_response.SftpResponseLimitsMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.extended_response.SftpResponseLimitsMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.extended_response.SftpResponseLimitsMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.extended_response.SftpResponseLimitsMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseLimitsMessageHandler
        extends SftpResponseMessageHandler<SftpResponseLimitsMessage> {

    public SftpResponseLimitsMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseLimitsMessageHandler(SshContext context, SftpResponseLimitsMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseLimitsMessageParser getParser(byte[] array) {
        return new SftpResponseLimitsMessageParser(array);
    }

    @Override
    public SftpResponseLimitsMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseLimitsMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseLimitsMessagePreparator getPreparator() {
        return new SftpResponseLimitsMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseLimitsMessageSerializer getSerializer() {
        return new SftpResponseLimitsMessageSerializer(message);
    }
}
