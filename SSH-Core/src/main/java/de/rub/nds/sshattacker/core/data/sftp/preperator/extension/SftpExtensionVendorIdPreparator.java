/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionVendorId;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionVendorIdPreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionVendorId> {

    public SftpExtensionVendorIdPreparator(Chooser chooser, SftpExtensionVendorId extension) {
        super(chooser, extension);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        getObject().setName(SftpExtension.VENDOR_ID, true);

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

        if (getObject().getVendorStructureLength() == null
                || getObject().getVendorStructureLength().getOriginalValue() == null) {
            getObject()
                    .setVendorStructureLength(
                            getObject().getVendorNameLength().getValue()
                                    + getObject().getProductNameLength().getValue()
                                    + getObject().getProductVersionLength().getValue()
                                    + DataFormatConstants.UINT64_SIZE);
        }
    }
}
