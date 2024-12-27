/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.holder;

import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.holder.SftpAclEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.holder.SftpAclEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.holder.SftpAclEntrySerializer;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class SftpAclEntryHandler implements Handler<SftpAclEntry> {

    private final SshContext context;

    private final SftpAclEntry aclEntry;

    public SftpAclEntryHandler(SshContext context) {
        this(context, null);
    }

    public SftpAclEntryHandler(SshContext context, SftpAclEntry aclEntry) {
        super();
        this.context = context;
        this.aclEntry = aclEntry;
    }

    @Override
    public void adjustContext() {}

    @Override
    public SftpAclEntryParser getParser(byte[] array) {
        return new SftpAclEntryParser(array);
    }

    @Override
    public SftpAclEntryParser getParser(byte[] array, int startPosition) {
        return new SftpAclEntryParser(array, startPosition);
    }

    public static final SftpAclEntryPreparator PREPARATOR = new SftpAclEntryPreparator();

    public static final SftpAclEntrySerializer SERIALIZER = new SftpAclEntrySerializer();
}
