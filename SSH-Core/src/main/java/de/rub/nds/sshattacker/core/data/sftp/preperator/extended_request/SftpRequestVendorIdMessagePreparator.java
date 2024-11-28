/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extended_request;

import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestVendorIdMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpRequestVendorIdMessagePreparator
        extends SftpRequestExtendedMessagePreparator<SftpRequestVendorIdMessage> {

    public SftpRequestVendorIdMessagePreparator(
            Chooser chooser, SftpRequestVendorIdMessage message) {
        super(chooser, message, SftpExtension.VENDOR_ID);
    }

    @Override
    public void prepareRequestExtendedSpecificContents() {
        getObject().setSoftlyVendorName("NDS RUB", true, chooser.getConfig());

        getObject().setSoftlyProductName("SSH-Attacker", true, chooser.getConfig());

        getObject().setSoftlyProductVersion("1.0", true, chooser.getConfig());

        getObject().setSoftlyProductBuildNumber(2024);
    }
}
