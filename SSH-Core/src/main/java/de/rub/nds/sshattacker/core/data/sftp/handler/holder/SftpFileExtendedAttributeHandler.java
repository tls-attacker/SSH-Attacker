/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpFileExtendedAttribute;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpFileExtendedAttributeParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpFileExtendedAttributePreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpFileExtendedAttributeSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpFileExtendedAttributeHandler implements Handler<SftpFileExtendedAttribute> {

    private final SshContext context;

    private final SftpFileExtendedAttribute attribute;

    public SftpFileExtendedAttributeHandler(SshContext context) {
        this(context, null);
    }

    public SftpFileExtendedAttributeHandler(
            SshContext context, SftpFileExtendedAttribute attribute) {
        super();
        this.context = context;
        this.attribute = attribute;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpFileExtendedAttributeParser getParser(byte[] array) {
        return new SftpFileExtendedAttributeParser(array);
    }

    @Override
    public SftpFileExtendedAttributeParser getParser(byte[] array, int startPosition) {
        return new SftpFileExtendedAttributeParser(array, startPosition);
    }

    @Override
    public SftpFileExtendedAttributePreparator getPreparator() {
        return new SftpFileExtendedAttributePreparator(context.getChooser(), attribute);
    }

    @Override
    public SftpFileExtendedAttributeSerializer getSerializer() {
        return new SftpFileExtendedAttributeSerializer(attribute);
    }
}
