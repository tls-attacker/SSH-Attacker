/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.common.parser.holder.SftpAclEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.common.preperator.holder.SftpAclEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.common.serializer.holder.SftpAclEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpAclEntryHandler implements Handler<SftpAclEntry> {

    @Override
    public void adjustContext(SshContext context, SftpAclEntry object) {}

    @Override
    public SftpAclEntryParser getParser(byte[] array, SshContext context) {
        return new SftpAclEntryParser(array);
    }

    @Override
    public SftpAclEntryParser getParser(byte[] array, int startPosition, SshContext context) {
        return new SftpAclEntryParser(array, startPosition);
    }

    public static final SftpAclEntryPreparator PREPARATOR = new SftpAclEntryPreparator();

    public static final SftpAclEntrySerializer SERIALIZER = new SftpAclEntrySerializer();
}
