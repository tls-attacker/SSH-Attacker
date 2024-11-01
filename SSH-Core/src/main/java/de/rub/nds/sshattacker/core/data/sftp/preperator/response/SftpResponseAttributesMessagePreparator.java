/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.data.sftp.message.attribute.SftpFileAttributes;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseAttributesMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseAttributesMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseAttributesMessage> {

    public SftpResponseAttributesMessagePreparator(
            Chooser chooser, SftpResponseAttributesMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_ATTRS);
    }

    @Override
    public void prepareResponseSpecificContents() {
        if (getObject().getAttributes() == null) {
            getObject().setAttributes(new SftpFileAttributes());
        }
        getObject().getAttributes().getHandler(chooser.getContext()).getPreparator().prepare();
    }
}
