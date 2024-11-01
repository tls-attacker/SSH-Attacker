/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestVendorIdMessage;
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
        LOGGER.debug("VendorName length: {}", message.getVendorNameLength().getValue());
        appendInt(message.getVendorNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "VendorName: {}", () -> backslashEscapeString(message.getVendorName().getValue()));
        appendString(message.getVendorName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductName() {
        LOGGER.debug("ProductName length: {}", message.getProductNameLength().getValue());
        appendInt(
                message.getProductNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ProductName: {}",
                () -> backslashEscapeString(message.getProductName().getValue()));
        appendString(message.getProductName().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductVersion() {
        LOGGER.debug("ProductVersion length: {}", message.getProductVersionLength().getValue());
        appendInt(
                message.getProductVersionLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug(
                "ProductVersion: {}",
                () -> backslashEscapeString(message.getProductVersion().getValue()));
        appendString(message.getProductVersion().getValue(), StandardCharsets.UTF_8);
    }

    private void serializeProductBuildNumber() {
        LOGGER.debug("ProductBuildNumber: {}", message.getProductBuildNumber().getValue());
        appendLong(message.getProductBuildNumber().getValue(), DataFormatConstants.UINT64_SIZE);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents() {
        serializeVendorName();
        serializeProductName();
        serializeProductVersion();
        serializeProductBuildNumber();
    }
}
