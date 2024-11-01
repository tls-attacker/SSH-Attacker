/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.parser.extended;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.data.sftp.message.extended.SftpRequestVendorIdMessage;
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
        message.setVendorNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("VendorName length: {}", message.getVendorNameLength().getValue());
        message.setVendorName(
                parseByteString(message.getVendorNameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "VendorName: {}", () -> backslashEscapeString(message.getVendorName().getValue()));
    }

    private void parseProductName() {
        message.setProductNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("ProductName length: {}", message.getProductNameLength().getValue());
        message.setProductName(
                parseByteString(message.getProductNameLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "ProductName: {}",
                () -> backslashEscapeString(message.getProductName().getValue()));
    }

    private void parseProductVersion() {
        message.setProductVersionLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("ProductVersion length: {}", message.getProductVersionLength().getValue());
        message.setProductVersion(
                parseByteString(
                        message.getProductVersionLength().getValue(), StandardCharsets.UTF_8));
        LOGGER.debug(
                "ProductVersion: {}",
                () -> backslashEscapeString(message.getProductVersion().getValue()));
    }

    private void parseProductBuildNumber() {
        message.setProductBuildNumber(parseLongField(DataFormatConstants.UINT64_SIZE));
        LOGGER.debug("ProductBuildNumber: {}", message.getProductBuildNumber().getValue());
    }

    @Override
    protected void parseRequestExtendedSpecificContents() {
        parseVendorName();
        parseProductName();
        parseProductVersion();
        parseProductBuildNumber();
    }
}
