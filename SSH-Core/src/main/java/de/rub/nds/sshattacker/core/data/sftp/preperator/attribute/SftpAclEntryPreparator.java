/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.attribute;

import de.rub.nds.sshattacker.core.constants.SftpAceFlag;
import de.rub.nds.sshattacker.core.constants.SftpAceMask;
import de.rub.nds.sshattacker.core.constants.SftpAceType;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpAclEntryPreparator extends Preparator<SftpAclEntry> {

    public SftpAclEntryPreparator(Chooser chooser, SftpAclEntry aclEntry) {
        super(chooser, aclEntry);
    }

    @Override
    public final void prepare() {
        if (getObject().getType() == null) {
            getObject().setType(SftpAceType.ACE4_ACCESS_ALLOWED_ACE_TYPE);
        }
        if (getObject().getFlags() == null) {
            getObject().setFlags(SftpAceFlag.ACE4_FILE_INHERIT_ACE);
        }
        if (getObject().getMask() == null) {
            getObject().setMask(SftpAceMask.ACE4_ADD_FILE);
        }

        if (getObject().getWho() == null) {
            getObject().setWho(chooser.getConfig().getUsername(), true);
        }
        if (getObject().getWhoLength() == null) {
            getObject().setWhoLength(getObject().getWho().getValue().length());
        }
    }
}
