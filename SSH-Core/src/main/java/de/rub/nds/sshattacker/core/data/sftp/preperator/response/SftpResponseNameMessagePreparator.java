/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseNameMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseNameMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseNameMessage> {

    public SftpResponseNameMessagePreparator(Chooser chooser, SftpResponseNameMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_NAME);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getCountNameEntries() == null || getObject().getCountNameEntries().getOriginalValue() == null) {
            getObject().setCountNameEntries(0);
        }

        getObject()
                .getNameEntries()
                .forEach(
                        nameEntry ->
                                nameEntry
                                        .getHandler(chooser.getContext())
                                        .getPreparator()
                                        .prepare());
    }
}
