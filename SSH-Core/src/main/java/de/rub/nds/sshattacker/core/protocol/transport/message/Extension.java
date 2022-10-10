/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.string.ModifiableString;

/*  class for extension
    structure:      extension-name
                    extension-value
*/

public class Extension {

    protected ModifiableString extensionName;

    protected ModifiableString extensionValue;

    protected int extensionNameLengthInBytes;

    protected int extensionValueLengthInBytes;

    public Extension(ModifiableString name, ModifiableString value) {
        this.extensionName = name;
        this.extensionValue = value;
        this.extensionNameLengthInBytes = this.extensionName.getOriginalValue().length();
        this.extensionValueLengthInBytes = this.extensionValue.getOriginalValue().length();
    }

    public void setExtensionName(String name) {
        this.extensionName.setOriginalValue(name);
    }

    public ModifiableString getExtensionName() {
        return this.extensionName;
    }

    public void setExtensionValue(String value) {
        this.extensionValue.setOriginalValue(value);
    }

    public ModifiableString getExtensionValue() {
        return this.extensionValue;
    }

    public void setExtensionNameLengthInBytes(int length) {
        this.extensionNameLengthInBytes = length;
    }

    public int getExtensionNameLengthInBytes() {
        return this.extensionNameLengthInBytes;
    }

    public void setExtensionValueLengthInBytes(int length) {
        this.extensionValueLengthInBytes = length;
    }

    public int getExtensionValueLengthInBytes() {
        return this.extensionValueLengthInBytes;
    }
}
