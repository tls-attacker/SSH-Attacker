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
        if (getObject().getVendorName() == null
                || getObject().getVendorName().getOriginalValue() == null) {
            getObject().setVendorName("NDS RUB", true);
        }
        if (getObject().getVendorNameLength() == null
                || getObject().getVendorNameLength().getOriginalValue() == null) {
            getObject().setVendorNameLength(getObject().getVendorName().getValue().length());
        }

        if (getObject().getProductName() == null
                || getObject().getProductName().getOriginalValue() == null) {
            getObject().setProductName("SSH-Attacker", true);
        }
        if (getObject().getProductNameLength() == null
                || getObject().getProductNameLength().getOriginalValue() == null) {
            getObject().setProductNameLength(getObject().getProductName().getValue().length());
        }

        if (getObject().getProductVersion() == null
                || getObject().getProductVersion().getOriginalValue() == null) {
            getObject().setProductVersion("1.0", true);
        }
        if (getObject().getProductVersionLength() == null
                || getObject().getProductVersionLength().getOriginalValue() == null) {
            getObject()
                    .setProductVersionLength(getObject().getProductVersion().getValue().length());
        }

        if (getObject().getProductBuildNumber() == null
                || getObject().getProductBuildNumber().getOriginalValue() == null) {
            getObject().setProductBuildNumber(2024);
        }
    }
}
