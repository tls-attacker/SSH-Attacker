/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseHandleMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseHandleMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseHandleMessage> {

    public SftpResponseHandleMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_HANDLE);
    }

    @Override
    public void prepareResponseSpecificContents(SftpResponseHandleMessage object, Chooser chooser) {
        if (object.getHandle() == null || object.getHandle().getOriginalValue() == null) {
            // Should be set in SftpManager handleRequestMessage() -> Don't use soft set, because
            // soft set in this case would set
            object.setHandle(new byte[100], true);
        }
        // This should not be necessary:
        object.setHandleLength(object.getHandle().getValue().length);
    }
}
