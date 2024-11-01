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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import java.nio.charset.StandardCharsets;

public abstract class SftpExtensionWithVersion<T extends SftpExtensionWithVersion<T>>
        extends SftpAbstractExtension<T> {
    private ModifiableString version;
    private ModifiableInteger versionLength;

    public ModifiableInteger getVersionLength() {
        return versionLength;
    }

    public void setVersionLength(ModifiableInteger versionLength) {
        this.versionLength = versionLength;
    }

    public void setVersionLength(int versionLength) {
        this.versionLength =
                ModifiableVariableFactory.safelySetValue(this.versionLength, versionLength);
    }

    public ModifiableString getVersion() {
        return version;
    }

    public void setVersion(ModifiableString version) {
        setVersion(version, false);
    }

    public void setVersion(String version) {
        setVersion(version, false);
    }

    public void setVersion(ModifiableString version, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVersionLength(version.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.version = version;
    }

    public void setVersion(String version, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVersionLength(version.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.version = ModifiableVariableFactory.safelySetValue(this.version, version);
    }
}
