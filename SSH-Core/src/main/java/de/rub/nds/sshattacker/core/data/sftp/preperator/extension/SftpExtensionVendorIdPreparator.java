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

        getObject().setSoftlyVendorName("NDS RUB", true, chooser.getConfig());

        getObject().setSoftlyProductName("SSH-Attacker", true, chooser.getConfig());

        getObject().setSoftlyProductVersion("1.0", true, chooser.getConfig());

        getObject().setSoftlyProductBuildNumber(2024);

        getObject()
                .setSoftlyVendorStructureLength(
                        getObject().getVendorNameLength().getValue()
                                + getObject().getProductNameLength().getValue()
                                + getObject().getProductVersionLength().getValue()
                                + DataFormatConstants.UINT64_SIZE,
                        chooser.getConfig());
    }
}
