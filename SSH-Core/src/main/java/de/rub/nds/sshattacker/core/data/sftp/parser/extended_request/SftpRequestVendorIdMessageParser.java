/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestVendorIdMessage;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestVendorIdMessageParser
        extends SftpRequestExtendedMessageParser<SftpRequestVendorIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public SftpRequestVendorIdMessageParser(byte[] array) {
        super(array);
    }

    public SftpRequestVendorIdMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    protected SftpRequestVendorIdMessage createMessage() {
        return new SftpRequestVendorIdMessage();
    }

    private void parseVendorName() {
        int vendorNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setVendorNameLength(vendorNameLength);
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        String vendorName = parseByteString(vendorNameLength, StandardCharsets.UTF_8);
        message.setVendorName(vendorName);
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
    }

    private void parseProductName() {
        int productNameLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setProductNameLength(productNameLength);
        LOGGER.debug("ProductName length: {}", productNameLength);
        String productName = parseByteString(productNameLength, StandardCharsets.UTF_8);
        message.setProductName(productName);
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
    }

    private void parseProductVersion() {
        int productVersionLength = parseIntField(DataFormatConstants.STRING_SIZE_LENGTH);
        message.setProductVersionLength(productVersionLength);
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        String productVersion = parseByteString(productVersionLength, StandardCharsets.UTF_8);
        message.setProductVersion(productVersion);
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
    }

    private void parseProductBuildNumber() {
        long productBuildNumber = parseLongField(DataFormatConstants.UINT64_SIZE);
        message.setProductBuildNumber(productBuildNumber);
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseVendorName();
        parseProductName();
        parseProductVersion();
        parseProductBuildNumber();
    }
}
