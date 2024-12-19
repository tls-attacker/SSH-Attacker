/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.holder;

import de.rub.nds.sshattacker.core.constants.SftpAceFlag;
import de.rub.nds.sshattacker.core.constants.SftpAceMask;
import de.rub.nds.sshattacker.core.constants.SftpAceType;
import de.rub.nds.sshattacker.core.data.sftp.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpAclEntryPreparator extends Preparator<SftpAclEntry> {

    public SftpAclEntryPreparator(Chooser chooser, SftpAclEntry aclEntry) {
        super(chooser, aclEntry);
    }

    @Override
    public final void prepare() {
        object.setSoftlyType(SftpAceType.ACE4_ACCESS_ALLOWED_ACE_TYPE);
        object.setSoftlyFlags(SftpAceFlag.ACE4_FILE_INHERIT_ACE);
        object.setSoftlyMask(SftpAceMask.ACE4_ADD_FILE);

        object.setSoftlyWho(config.getUsername(), true, config);
    }
}
