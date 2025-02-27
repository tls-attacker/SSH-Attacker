/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.common.serializer.extension;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.sshattacker.core.data.sftp.common.message.extension.SftpExtensionVendorId;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SftpExtensionVendorIdSerializer
        extends SftpAbstractExtensionSerializer<SftpExtensionVendorId> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializeVendorStructureLength(
            SftpExtensionVendorId object, SerializerStream output) {
        Integer vendorStructureLength = object.getVendorStructureLength().getValue();
        LOGGER.debug("VendorStructureLength: {}", vendorStructureLength);
        output.appendInt(vendorStructureLength);
    }

    private static void serializeVendorName(SftpExtensionVendorId object, SerializerStream output) {
        Integer vendorNameLength = object.getVendorNameLength().getValue();
        LOGGER.debug("VendorName length: {}", vendorNameLength);
        output.appendInt(vendorNameLength);
        String vendorName = object.getVendorName().getValue();
        LOGGER.debug("VendorName: {}", () -> backslashEscapeString(vendorName));
        output.appendString(vendorName, StandardCharsets.UTF_8);
    }

    private static void serializeProductName(
            SftpExtensionVendorId object, SerializerStream output) {
        Integer productNameLength = object.getProductNameLength().getValue();
        LOGGER.debug("ProductName length: {}", productNameLength);
        output.appendInt(productNameLength);
        String productName = object.getProductName().getValue();
        LOGGER.debug("ProductName: {}", () -> backslashEscapeString(productName));
        output.appendString(productName, StandardCharsets.UTF_8);
    }

    private static void serializeProductVersion(
            SftpExtensionVendorId object, SerializerStream output) {
        Integer productVersionLength = object.getProductVersionLength().getValue();
        LOGGER.debug("ProductVersion length: {}", productVersionLength);
        output.appendInt(productVersionLength);
        String productVersion = object.getProductVersion().getValue();
        LOGGER.debug("ProductVersion: {}", () -> backslashEscapeString(productVersion));
        output.appendString(productVersion, StandardCharsets.UTF_8);
    }

    private static void serializeProductBuildNumber(
            SftpExtensionVendorId object, SerializerStream output) {
        Long productBuildNumber = object.getProductBuildNumber().getValue();
        LOGGER.debug("ProductBuildNumber: {}", productBuildNumber);
        output.appendLong(productBuildNumber);
    }

    @Override
    protected void serializeExtensionValue(SftpExtensionVendorId object, SerializerStream output) {
        serializeVendorStructureLength(object, output);
        serializeVendorName(object, output);
        serializeProductName(object, output);
        serializeProductVersion(object, output);
        serializeProductBuildNumber(object, output);
    }
}
