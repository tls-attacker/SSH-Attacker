/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.handler.attribute;

import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpAclEntry;
import de.rub.nds.sshattacker.core.data.sftp.parser.attribute.SftpAclEntryParser;
import de.rub.nds.sshattacker.core.data.sftp.preperator.attribute.SftpAclEntryPreparator;
import de.rub.nds.sshattacker.core.data.sftp.serializer.attribute.SftpAclEntrySerializer;
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

    @Override
    public SftpAclEntryPreparator getPreparator() {
        return new SftpAclEntryPreparator(context.getChooser(), aclEntry);
    }

    @Override
    public SftpAclEntrySerializer getSerializer() {
        return new SftpAclEntrySerializer(aclEntry);
    }
}
