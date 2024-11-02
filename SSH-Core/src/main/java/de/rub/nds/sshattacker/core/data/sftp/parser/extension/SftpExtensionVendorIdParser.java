/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extension.SftpExtensionVendorId;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionVendorIdParser
        extends SftpAbstractExtensionParser<SftpExtensionVendorId> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpExtensionVendorIdParser(byte[] array) {
        super(SftpExtensionVendorId::new, array);
    }

    public SftpExtensionVendorIdParser(byte[] array, int startPosition) {
        super(SftpExtensionVendorId::new, array, startPosition);
    }

    private void parseVendorStructureLength() {
        int vendorStructureLength = parseIntField(DataFormatConstants.UINT32_SIZE);
        extension.setVendorStructureLength(vendorStructureLength);
        LOGGER.debug("VendorStructureLength: {}", vendorStructureLength);
    }

    private void parseVendorName() {
        int vendorNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        extension.setVendorNameLength(vendorNameLength);
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        String vendorName = parseByteString(vendorNameLength, StandardCharsets.UTF_8);
        extension.setVendorName(vendorName);
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
    }

    private void parseProductName() {
        int productNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        extension.setProductNameLength(productNameLength);
        LOGGER.debug("ProductName length: {}", productNameLength);
        String productName = parseByteString(productNameLength, StandardCharsets.UTF_8);
        extension.setProductName(productName);
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
    }

    private void parseProductVersion() {
        int productVersionLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        extension.setProductVersionLength(productVersionLength);
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        String productVersion = parseByteString(productVersionLength, StandardCharsets.UTF_8);
        extension.setProductVersion(productVersion);
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
    }

    private void parseProductBuildNumber() {
        long productBuildNumber = parseLongField(DataFormatConstants.UINT64_SIZE);
        extension.setProductBuildNumber(productBuildNumber);
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
    }

    @Override
    protected void parseExtensionValue() {
        parseVendorStructureLength();
        parseVendorName();
        parseProductName();
        parseProductVersion();
        parseProductBuildNumber();
    }
}
