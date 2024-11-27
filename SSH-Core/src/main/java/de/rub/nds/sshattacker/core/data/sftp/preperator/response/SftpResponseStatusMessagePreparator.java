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
        if (getObject().getStatusCode() == null || getObject().getStatusCode().getOriginalValue() == null) {
            getObject().setStatusCode(SftpStatusCode.SSH_FX_OK);
        }

        if (getObject().getErrorMessage() == null || getObject().getErrorMessage().getOriginalValue() == null) {
            getObject().setErrorMessage("SSH-Attacker sagt NEIN!", true);
        }
        if (getObject().getErrorMessageLength() == null || getObject().getErrorMessageLength().getOriginalValue() == null) {
            getObject().setErrorMessageLength(getObject().getErrorMessage().getValue().length());
        }

        if (getObject().getLanguageTag() == null || getObject().getLanguageTag().getOriginalValue() == null) {
            getObject().setLanguageTag("de", true);
        }
        if (getObject().getLanguageTagLength() == null || getObject().getLanguageTagLength().getOriginalValue() == null) {
            getObject().setLanguageTagLength(getObject().getLanguageTag().getValue().length());
        }
    }
}
