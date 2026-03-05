/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.holder;

import de.rub.nds.sshattacker.core.constants.SftpAceFlag;
import de.rub.nds.sshattacker.core.constants.SftpAceMask;
import de.rub.nds.sshattacker.core.constants.SftpAceType;
import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpAclEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpAclEntryPreparator extends Preparator<SftpAclEntry> {

    @Override
    public final void prepare(SftpAclEntry object, Chooser chooser) {
        object.setType(SftpAceType.ACE4_ACCESS_ALLOWED_ACE_TYPE);
        object.setFlags(SftpAceFlag.ACE4_FILE_INHERIT_ACE);
        object.setMask(SftpAceMask.ACE4_ADD_FILE);

        object.setWho(chooser.getConfig().getUsername(), true);
    }
}
