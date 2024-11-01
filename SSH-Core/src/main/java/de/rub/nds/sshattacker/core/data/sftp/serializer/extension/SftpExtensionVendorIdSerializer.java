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

    private void serializeVendorName() {
        LOGGER.debug("VendorName length: {}", extension.getVendorNameLength().getValue());
        appendInt(
                extension.getVendorNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "VendorName: {}",
                () -> backslashEscapeString(extension.getVendorName().getValue()));
        appendString(extension.getVendorName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductName() {
        LOGGER.debug("ProductName length: {}", extension.getProductNameLength().getValue());
        appendInt(
                extension.getProductNameLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ProductName: {}",
                () -> backslashEscapeString(extension.getProductName().getValue()));
        appendString(extension.getProductName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductVersion() {
        LOGGER.debug("ProductVersion length: {}", extension.getProductVersionLength().getValue());
        appendInt(
                extension.getProductVersionLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ProductVersion: {}",
                () -> backslashEscapeString(extension.getProductVersion().getValue()));
        appendString(extension.getProductVersion().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductBuildNumber() {
        LOGGER.debug("ProductBuildNumber: {}", extension.getProductBuildNumber().getValue());
        appendLong(extension.getProductBuildNumber().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeExtensionValue() {
        serializeVendorName();
        serializeProductName();
        serializeProductVersion();
        serializeProductBuildNumber();
    }
}
