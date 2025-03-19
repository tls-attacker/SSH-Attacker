/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.common.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.response.SftpResponseAttributesMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.response.SftpResponseAttributesMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.response.SftpResponseAttributesMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpResponseAttributesMessageHandler
        extends SftpResponseMessageHandler<SftpResponseAttributesMessage> {

    @Override
    public SftpResponseAttributesMessageParser getParser(byte[] array, SshContext context) {
        return new SftpResponseAttributesMessageParser(array);
    }

    @Override
    public SftpResponseAttributesMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpResponseAttributesMessageParser(array, startPosition);
    }

    public static final SftpResponseAttributesMessagePreparator PREPARATOR =
            new SftpResponseAttributesMessagePreparator();

    public static final SftpResponseAttributesMessageSerializer SERIALIZER =
            new SftpResponseAttributesMessageSerializer();
}
