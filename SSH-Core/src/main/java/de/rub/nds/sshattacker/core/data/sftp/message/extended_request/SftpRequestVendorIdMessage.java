/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extended_request;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.sftp.handler.extended_request.SftpRequestVendorIdMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class SftpRequestVendorIdMessage
        extends SftpRequestExtendedMessage<SftpRequestVendorIdMessage> {

    private ModifiableInteger vendorNameLength;
    private ModifiableString vendorName;
    private ModifiableInteger productNameLength;
    private ModifiableString productName;
    private ModifiableInteger productVersionLength;
    private ModifiableString productVersion;
    private ModifiableLong productBuildNumber;

    public ModifiableInteger getVendorNameLength() {
        return vendorNameLength;
    }

    public void setVendorNameLength(ModifiableInteger vendorNameLength) {
        this.vendorNameLength = vendorNameLength;
    }

    public void setVendorNameLength(int vendorNameLength) {
        this.vendorNameLength =
                ModifiableVariableFactory.safelySetValue(this.vendorNameLength, vendorNameLength);
    }

    public ModifiableString getVendorName() {
        return vendorName;
    }

    public void setVendorName(ModifiableString vendorName) {
        setVendorName(vendorName, false);
    }

    public void setVendorName(String vendorName) {
        setVendorName(vendorName, false);
    }

    public void setVendorName(ModifiableString vendorName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVendorNameLength(vendorName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.vendorName = vendorName;
    }

    public void setVendorName(String vendorName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVendorNameLength(vendorName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.vendorName = ModifiableVariableFactory.safelySetValue(this.vendorName, vendorName);
    }

    public ModifiableInteger getProductNameLength() {
        return productNameLength;
    }

    public void setProductNameLength(ModifiableInteger productNameLength) {
        this.productNameLength = productNameLength;
    }

    public void setProductNameLength(int productNameLength) {
        this.productNameLength =
                ModifiableVariableFactory.safelySetValue(this.productNameLength, productNameLength);
    }

    public ModifiableString getProductName() {
        return productName;
    }

    public void setProductName(ModifiableString productName) {
        setProductName(productName, false);
    }

    public void setProductName(String productName) {
        setProductName(productName, false);
    }

    public void setProductName(ModifiableString productName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setProductNameLength(productName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.productName = productName;
    }

    public void setProductName(String productName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setProductNameLength(productName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.productName = ModifiableVariableFactory.safelySetValue(this.productName, productName);
    }

    public ModifiableInteger getProductVersionLength() {
        return productVersionLength;
    }

    public void setProductVersionLength(ModifiableInteger productVersionLength) {
        this.productVersionLength = productVersionLength;
    }

    public void setProductVersionLength(int productVersionLength) {
        this.productVersionLength =
                ModifiableVariableFactory.safelySetValue(
                        this.productVersionLength, productVersionLength);
    }

    public ModifiableString getProductVersion() {
        return productVersion;
    }

    public void setProductVersion(ModifiableString productVersion) {
        setProductVersion(productVersion, false);
    }

    public void setProductVersion(String productVersion) {
        setProductVersion(productVersion, false);
    }

    public void setProductVersion(ModifiableString productVersion, boolean adjustLengthField) {
        if (adjustLengthField) {
            setProductVersionLength(
                    productVersion.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.productVersion = productVersion;
    }

    public void setProductVersion(String productVersion, boolean adjustLengthField) {
        if (adjustLengthField) {
            setProductVersionLength(productVersion.getBytes(StandardCharsets.UTF_8).length);
        }
        this.productVersion =
                ModifiableVariableFactory.safelySetValue(this.productVersion, productVersion);
    }

    public ModifiableLong getProductBuildNumber() {
        return productBuildNumber;
    }

    public void setProductBuildNumber(ModifiableLong productBuildNumber) {
        this.productBuildNumber = productBuildNumber;
    }

    public void setProductBuildNumber(long productBuildNumber) {
        this.productBuildNumber =
                ModifiableVariableFactory.safelySetValue(
                        this.productBuildNumber, productBuildNumber);
    }

    @Override
    public SftpRequestVendorIdMessageHandler getHandler(SshContext context) {
        return new SftpRequestVendorIdMessageHandler(context, this);
    }
}
