/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.preperator.extension;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionVendorId;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class SftpExtensionVendorIdPreparator
        extends SftpAbstractExtensionPreparator<SftpExtensionVendorId> {

    public SftpExtensionVendorIdPreparator() {
        super(SftpExtension.VENDOR_ID);
    }

    @Override
    public void prepareExtensionSpecificContents(SftpExtensionVendorId object, Chooser chooser) {
        Config config = chooser.getConfig();
        object.setVendorName("NDS RUB", true);

        object.setProductName("SSH-Attacker", true);

        object.setProductVersion("1.0", true);

        object.setProductBuildNumber(2024);

        object.setVendorStructureLength(
                object.getVendorNameLength().getValue()
                        + object.getProductNameLength().getValue()
                        + object.getProductVersionLength().getValue()
                        + DataFormatConstants.UINT64_SIZE);
    }
}
