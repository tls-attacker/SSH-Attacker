/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionVendorId;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionVendorIdSerializer
        extends SftpAbstractExtensionSerializer<SftpExtensionVendorId> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionVendorIdSerializer(SftpExtensionVendorId extension) {
        super(extension);
    }

    private void serializeVendorStructureLength() {
        Integer vendorStructureLength = extension.getVendorStructureLength().getValue();
        LOGGER.debug("VendorStructureLength: {}", vendorStructureLength);
        appendInt(vendorStructureLength, DataFormatConstants.UINT32_SIZE);
    }

    private void serializeVendorName() {
        Integer vendorNameLength = extension.getVendorNameLength().getValue();
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        appendInt(vendorNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String vendorName = extension.getVendorName().getValue();
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
        appendString(vendorName, StandardCharsets.UTF_8);
    }

    private void serializeProductName() {
        Integer productNameLength = extension.getProductNameLength().getValue();
        LOGGER.debug("ProductName length: {}", productNameLength);
        appendInt(productNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String productName = extension.getProductName().getValue();
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
        appendString(productName, StandardCharsets.UTF_8);
    }

    private void serializeProductVersion() {
        Integer productVersionLength = extension.getProductVersionLength().getValue();
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        appendInt(productVersionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String productVersion = extension.getProductVersion().getValue();
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
        appendString(productVersion, StandardCharsets.UTF_8);
    }

    private void serializeProductBuildNumber() {
        Long productBuildNumber = extension.getProductBuildNumber().getValue();
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
        appendLong(productBuildNumber, DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeExtensionValue() {
        serializeVendorStructureLength();
        serializeVendorName();
        serializeProductName();
        serializeProductVersion();
        serializeProductBuildNumber();
    }
}
