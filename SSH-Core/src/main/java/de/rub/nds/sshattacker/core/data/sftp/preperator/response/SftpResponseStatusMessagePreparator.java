/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.response;

import de.rub.nds.sshattacker.core.constants.SftpPacketTypeConstant;
import de.rub.nds.sshattacker.core.constants.SftpStatusCode;
import de.rub.nds.sshattacker.core.data.sftp.message.response.SftpResponseStatusMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpResponseStatusMessagePreparator
        extends SftpResponseMessagePreparator<SftpResponseStatusMessage> {

    public SftpResponseStatusMessagePreparator(Chooser chooser, SftpResponseStatusMessage message) {
        super(chooser, message, SftpPacketTypeConstant.SSH_FXP_STATUS);
    }

    @Override
    public void prepareResponseSpecificContents() {
        getObject().setSoftlyStatusCode(SftpStatusCode.SSH_FX_OK);

        getObject().setSoftlyErrorMessage("SSH-Attacker sagt NEIN!", true, chooser.getConfig());

        getObject().setSoftlyLanguageTag("de", true, chooser.getConfig());
    }
}
