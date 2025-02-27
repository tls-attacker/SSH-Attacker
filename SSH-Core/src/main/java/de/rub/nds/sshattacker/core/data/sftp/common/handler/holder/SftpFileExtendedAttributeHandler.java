/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpFileExtendedAttributeParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.holder.SftpFileExtendedAttributePreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder.SftpFileExtendedAttributeSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpFileExtendedAttributeHandler implements Handler<SftpFileExtendedAttribute> {

    @Override
    public void adjustContext(SshContext context, SftpFileExtendedAttribute object) {}

    @Override
    public SftpFileExtendedAttributeParser getParser(byte[] array, SshContext context) {
        return new SftpFileExtendedAttributeParser(array);
    }

    @Override
    public SftpFileExtendedAttributeParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new SftpFileExtendedAttributeParser(array, startPosition);
    }

    public static final SftpFileExtendedAttributePreparator PREPARATOR =
            new SftpFileExtendedAttributePreparator();

    public static final SftpFileExtendedAttributeSerializer SERIALIZER =
            new SftpFileExtendedAttributeSerializer();
}
