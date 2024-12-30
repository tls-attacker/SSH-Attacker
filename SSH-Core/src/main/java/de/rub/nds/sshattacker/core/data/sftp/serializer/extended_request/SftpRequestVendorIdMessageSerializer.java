/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.serializer.extended_request;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.message.extended_request.SftpRequestVendorIdMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpRequestVendorIdMessageSerializer
        extends SftpRequestExtendedMessageSerializer<SftpRequestVendorIdMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeVendorName(
            SftpRequestVendorIdMessage object, SerializerStream output) {
        Integer vendorNameLength = object.getVendorNameLength().getValue();
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        output.appendInt(vendorNameLength);
        String vendorName = object.getVendorName().getValue();
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
        output.appendString(vendorName, StandardCharsets.UTF_8);
    }

    private static void serializeProductName(
            SftpRequestVendorIdMessage object, SerializerStream output) {
        Integer productNameLength = object.getProductNameLength().getValue();
        LOGGER.debug("ProductName length: {}", productNameLength);
        output.appendInt(productNameLength);
        String productName = object.getProductName().getValue();
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
        output.appendString(productName, StandardCharsets.UTF_8);
    }

    private static void serializeProductVersion(
            SftpRequestVendorIdMessage object, SerializerStream output) {
        Integer productVersionLength = object.getProductVersionLength().getValue();
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        output.appendInt(productVersionLength);
        String productVersion = object.getProductVersion().getValue();
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
        output.appendString(productVersion, StandardCharsets.UTF_8);
    }

    private static void serializeProductBuildNumber(
            SftpRequestVendorIdMessage object, SerializerStream output) {
        Long productBuildNumber = object.getProductBuildNumber().getValue();
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
        output.appendLong(productBuildNumber);
    }

    @Override
    protected void serializeRequestExtendedSpecificContents(
            SftpRequestVendorIdMessage object, SerializerStream output) {
        serializeVendorName(object, output);
        serializeProductName(object, output);
        serializeProductVersion(object, output);
        serializeProductBuildNumber(object, output);
    }
}
