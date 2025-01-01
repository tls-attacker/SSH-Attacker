/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.sftp.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.longint.ModifiableLong;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpExtensionVendorIdHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class SftpExtensionVendorId extends SftpAbstractExtension<SftpExtensionVendorId> {

    private ModifiableInteger vendorStructureLength;
    private ModifiableInteger vendorNameLength;
    private ModifiableString vendorName;
    private ModifiableInteger productNameLength;
    private ModifiableString productName;
    private ModifiableInteger productVersionLength;
    private ModifiableString productVersion;
    private ModifiableLong productBuildNumber;

    public SftpExtensionVendorId() {
        super();
    }

    public SftpExtensionVendorId(SftpExtensionVendorId other) {
        super(other);
        vendorStructureLength =
                other.vendorStructureLength != null
                        ? other.vendorStructureLength.createCopy()
                        : null;
        vendorNameLength =
                other.vendorNameLength != null ? other.vendorNameLength.createCopy() : null;
        vendorName = other.vendorName != null ? other.vendorName.createCopy() : null;
        productNameLength =
                other.productNameLength != null ? other.productNameLength.createCopy() : null;
        productName = other.productName != null ? other.productName.createCopy() : null;
        productVersionLength =
                other.productVersionLength != null ? other.productVersionLength.createCopy() : null;
        productVersion = other.productVersion != null ? other.productVersion.createCopy() : null;
        productBuildNumber =
                other.productBuildNumber != null ? other.productBuildNumber.createCopy() : null;
    }

    @Override
    public SftpExtensionVendorId createCopy() {
        return new SftpExtensionVendorId(this);
    }

    public ModifiableInteger getVendorStructureLength() {
        return vendorStructureLength;
    }

    public void setVendorStructureLength(ModifiableInteger vendorStructureLength) {
        this.vendorStructureLength = vendorStructureLength;
    }

    public void setVendorStructureLength(int vendorStructureLength) {
        this.vendorStructureLength =
                ModifiableVariableFactory.safelySetValue(
                        this.vendorStructureLength, vendorStructureLength);
    }

    public void setSoftlyVendorStructureLength(int vendorStructureLength, Config config) {
        if (config.getAlwaysPrepareSftpLengthFields()
                || this.vendorStructureLength == null
                || this.vendorStructureLength.getOriginalValue() == null) {

            this.vendorStructureLength =
                    ModifiableVariableFactory.safelySetValue(
                            this.vendorStructureLength, vendorStructureLength);
        }
    }

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
        this.vendorName = ModifiableVariableFactory.safelySetValue(this.vendorName, vendorName);
        if (adjustLengthField) {
            setVendorNameLength(this.vendorName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyVendorName(String vendorName, boolean adjustLengthField, Config config) {
        if (this.vendorName == null || this.vendorName.getOriginalValue() == null) {
            this.vendorName = ModifiableVariableFactory.safelySetValue(this.vendorName, vendorName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || vendorNameLength == null
                    || vendorNameLength.getOriginalValue() == null) {
                setVendorNameLength(
                        this.vendorName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
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
        this.productName = ModifiableVariableFactory.safelySetValue(this.productName, productName);
        if (adjustLengthField) {
            setProductNameLength(
                    this.productName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyProductName(String productName, boolean adjustLengthField, Config config) {
        if (this.productName == null || this.productName.getOriginalValue() == null) {
            this.productName =
                    ModifiableVariableFactory.safelySetValue(this.productName, productName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || productNameLength == null
                    || productNameLength.getOriginalValue() == null) {
                setProductNameLength(
                        this.productName.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
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
        this.productVersion =
                ModifiableVariableFactory.safelySetValue(this.productVersion, productVersion);
        if (adjustLengthField) {
            setProductVersionLength(
                    this.productVersion.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSoftlyProductVersion(
            String productVersion, boolean adjustLengthField, Config config) {
        if (this.productVersion == null || this.productVersion.getOriginalValue() == null) {
            this.productVersion =
                    ModifiableVariableFactory.safelySetValue(this.productVersion, productVersion);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareSftpLengthFields()
                    || productVersionLength == null
                    || productVersionLength.getOriginalValue() == null) {
                setProductVersionLength(
                        this.productVersion.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
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

    public void setSoftlyProductBuildNumber(long productBuildNumber) {
        if (this.productBuildNumber == null || this.productBuildNumber.getOriginalValue() == null) {
            this.productBuildNumber =
                    ModifiableVariableFactory.safelySetValue(
                            this.productBuildNumber, productBuildNumber);
        }
    }

    public static final SftpExtensionVendorIdHandler HANDLER = new SftpExtensionVendorIdHandler();

    @Override
    public SftpExtensionVendorIdHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        SftpExtensionVendorIdHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return SftpExtensionVendorIdHandler.SERIALIZER.serialize(this);
    }
}
