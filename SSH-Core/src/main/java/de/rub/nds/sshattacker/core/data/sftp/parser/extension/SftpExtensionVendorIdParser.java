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

    private void parseVendorName() {
        extension.setVendorNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("VendorName length: {}", extension.getVendorNameLength().getValue());
        extension.setVendorName(
                parseByteString(
                        extension.getVendorNameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "VendorName: {}",
                () -> backslashEscapeString(extension.getVendorName().getValue()));
    }

    private void parseProductName() {
        extension.setProductNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("ProductName length: {}", extension.getProductNameLength().getValue());
        extension.setProductName(
                parseByteString(
                        extension.getProductNameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "ProductName: {}",
                () -> backslashEscapeString(extension.getProductName().getValue()));
    }

    private void parseProductVersion() {
        extension.setProductVersionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("ProductVersion length: {}", extension.getProductVersionLength().getValue());
        extension.setProductVersion(
                parseByteString(
                        extension.getProductVersionLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "ProductVersion: {}",
                () -> backslashEscapeString(extension.getProductVersion().getValue()));
    }

    private void parseProductBuildNumber() {
        extension.setProductBuildNumber(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("ProductBuildNumber: {}", extension.getProductBuildNumber().getValue());
    }

    @Override
    protected void parseExtensionValue() {
        parseVendorName();
        parseProductName();
        parseProductVersion();
        parseProductBuildNumber();
    }
}
