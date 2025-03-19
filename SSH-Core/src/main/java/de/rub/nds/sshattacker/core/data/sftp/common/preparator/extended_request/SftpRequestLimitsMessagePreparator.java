/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.preparator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.common.message.extended_request.SftpRequestLimitsMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestLimitsMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestLimitsMessage> {

    public SftpRequestLimitsMessagePreparator() {
        super(SftpExtension.LIMITS_OPENSSH_COM);
    }

    @Override
    public void prepareRequestExtendedSpecificContents(
            SftpRequestLimitsMessage object, Chooser chooser) {}
}
