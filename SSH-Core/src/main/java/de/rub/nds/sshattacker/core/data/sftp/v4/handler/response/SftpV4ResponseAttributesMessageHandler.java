/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.handler.response;

import de.rub.nds.sshattacker.core.data.sftp.common.handler.response.SftpResponseMessageHandler;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseAttributesMessage;
import de.rub.nds.sshattacker.core.data.sftp.v4.parser.response.SftpV4ResponseAttributesMessageParser;
import de.rub.nds.sshattacker.core.data.sftp.v4.preparator.response.SftpV4ResponseAttributesMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.serializer.response.SftpV4ResponseAttributesMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpV4ResponseAttributesMessageHandler
        extends SftpResponseMessageHandler<SftpV4ResponseAttributesMessage> {

    @Override
    public SftpV4ResponseAttributesMessageParser getParser(byte[] array, SshContext context) {
        return new SftpV4ResponseAttributesMessageParser(array);
    }

    @Override
    public SftpV4ResponseAttributesMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpV4ResponseAttributesMessageParser(array, startPosition);
    }

    public static final SftpV4ResponseAttributesMessagePreparator PREPARATOR =
            new SftpV4ResponseAttributesMessagePreparator();

    public static final SftpV4ResponseAttributesMessageSerializer SERIALIZER =
            new SftpV4ResponseAttributesMessageSerializer();
}
