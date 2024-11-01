/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseDataMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseDataMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseDataMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseDataMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseDataMessageHandler extends SftpMessageHandler<SftpResponseDataMessage> {

    public SftpResponseDataMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseDataMessageHandler(SshContext context, SftpResponseDataMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle SftpResponseDataMessage
    }

    @Override
    public SftpResponseDataMessageParser getParser(byte[] array) {
        return new SftpResponseDataMessageParser(array);
    }

    @Override
    public SftpResponseDataMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseDataMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseDataMessagePreparator getPreparator() {
        return new SftpResponseDataMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseDataMessageSerializer getSerializer() {
        return new SftpResponseDataMessageSerializer(message);
    }
}
