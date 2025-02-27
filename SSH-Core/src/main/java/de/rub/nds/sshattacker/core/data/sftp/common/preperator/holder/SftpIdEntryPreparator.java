/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preperator.holder;

import de.rub.nds.sshattacker.core.data.sftp.common.message.holder.SftpIdEntry;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpIdEntryPreparator extends Preparator<SftpIdEntry> {

    @Override
    public final void prepare(SftpIdEntry object, Chooser chooser) {
        object.setId(1000);
    }
}
