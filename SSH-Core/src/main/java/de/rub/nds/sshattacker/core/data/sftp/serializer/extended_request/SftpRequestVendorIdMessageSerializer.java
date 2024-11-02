/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestVendorIdMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestVendorIdMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestVendorIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestVendorIdMessageSerializer(SftpRequestVendorIdMessage message) {
        super(message);
    }

    private void serializeVendorName() {
        Integer vendorNameLength = message.getVendorNameLength().getValue();
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        appendInt(vendorNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String vendorName = message.getVendorName().getValue();
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
        appendString(vendorName, StandardCharsets.UTF_8);
    }

    private void serializeProductName() {
        Integer productNameLength = message.getProductNameLength().getValue();
        LOGGER.debug("ProductName length: {}", productNameLength);
        appendInt(productNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String productName = message.getProductName().getValue();
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
        appendString(productName, StandardCharsets.UTF_8);
    }

    private void serializeProductVersion() {
        Integer productVersionLength = message.getProductVersionLength().getValue();
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        appendInt(productVersionLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String productVersion = message.getProductVersion().getValue();
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
        appendString(productVersion, StandardCharsets.UTF_8);
    }

    private void serializeProductBuildNumber() {
        Long productBuildNumber = message.getProductBuildNumber().getValue();
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
        appendLong(productBuildNumber, DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeVendorName();
        serializeProductName();
        serializeProductVersion();
        serializeProductBuildNumber();
    }
}
