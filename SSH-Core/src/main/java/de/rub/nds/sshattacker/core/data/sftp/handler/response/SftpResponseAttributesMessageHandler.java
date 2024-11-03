/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.*;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseAttributesMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseAttributesMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseAttributesMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseAttributesMessageHandler
        extends SftpResponseMessageHandler<SftpResponseAttributesMessage> {

    public SftpResponseAttributesMessageHandler(SshContext context) {
        super(context);
    }

    public SftpResponseAttributesMessageHandler(
            SshContext context, SftpResponseAttributesMessage message) {
        super(context, message);
    }

    @Override
    public SftpResponseAttributesMessageParser getParser(byte[] array) {
        return new SftpResponseAttributesMessageParser(array);
    }

    @Override
    public SftpResponseAttributesMessageParser getParser(byte[] array, int startPosition) {
        return new SftpResponseAttributesMessageParser(array, startPosition);
    }

    @Override
    public SftpResponseAttributesMessagePreparator getPreparator() {
        return new SftpResponseAttributesMessagePreparator(context.getChooser(), message);
    }

    @Override
    public SftpResponseAttributesMessageSerializer getSerializer() {
        return new SftpResponseAttributesMessageSerializer(message);
    }
}
