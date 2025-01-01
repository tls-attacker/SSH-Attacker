/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.parser.response.SftpResponseAttributesMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.response.SftpResponseAttributesMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.response.SftpResponseAttributesMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseAttributesMessageHandler
        extends SftpResponseMessageHandler<SftpResponseAttributesMessage> {

    @Override
    public SftpResponseAttributesMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseAttributesMessageParser(array, context.getChooser());
    }

    @Override
    public SftpResponseAttributesMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseAttributesMessageParser(array, startPosition, context.getChooser());
    }

    public static final SftpResponseAttributesMessagePreparator PREPARATOR =
            new SftpResponseAttributesMessagePreparator();

    public static final SftpResponseAttributesMessageSerializer SERIALIZER =
            new SftpResponseAttributesMessageSerializer();
}
