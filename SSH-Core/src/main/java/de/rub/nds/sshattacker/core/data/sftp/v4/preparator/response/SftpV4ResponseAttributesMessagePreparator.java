/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.v4.preparator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.common.preparator.response.SftpResponseMessagePreparator;
import de.rub.nds.sshattacker.core.data.sftp.v4.message.response.SftpV4ResponseAttributesMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpV4ResponseAttributesMessagePreparator
        extends SftpResponseMessagePreparator<SftpV4ResponseAttributesMessage> {

    public SftpV4ResponseAttributesMessagePreparator() {
        super(SftpPacketTypeConstant.SSH_FXP_ATTRS);
    }

    @Override
    protected void prepareResponseSpecificContents(
            SftpV4ResponseAttributesMessage object, Chooser chooser) {
        object.getAttributes().prepare(chooser);
    }
}
