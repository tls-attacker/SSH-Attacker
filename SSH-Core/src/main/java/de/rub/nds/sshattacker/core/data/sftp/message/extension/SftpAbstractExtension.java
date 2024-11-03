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
import de.rub.nds.sshattacker.core.constants.SftpExtension;
import de.rub.nds.sshattacker.core.data.sftp.handler.extension.SftpAbstractExtensionHandler;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.state.SshContext;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import java.nio.charset.StandardCharsets;

@XmlAccessorType(XmlAccessType.FIELD)
public abstract class SftpAbstractExtension<E extends SftpAbstractExtension<E>>
        extends ModifiableVariableHolder {

    protected ModifiableInteger nameLength;

    protected ModifiableString name;

    public ModifiableInteger getNameLength() {
        return nameLength;
    }

    public void setNameLength(ModifiableInteger nameLength) {
        this.nameLength = nameLength;
    }

    public void setNameLength(int nameLength) {
        this.nameLength = ModifiableVariableFactory.safelySetValue(this.nameLength, nameLength);
    }

    public ModifiableString getName() {
        return name;
    }

    public void setName(ModifiableString name) {
        setName(name, false);
    }

    public void setName(String name) {
        setName(name, false);
    }

    public void setName(SftpExtension extension) {
        setName(extension.getName(), false);
    }

    public void setName(ModifiableString name, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameLength(name.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.name = name;
    }

    public void setName(String name, boolean adjustLengthField) {
        if (adjustLengthField) {
            setNameLength(name.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.name = ModifiableVariableFactory.safelySetValue(this.name, name);
    }

    public void setName(SftpExtension extension, boolean adjustLengthField) {
        setName(extension.getName(), adjustLengthField);
    }

    public abstract SftpAbstractExtensionHandler<E> getHandler(SshContext context);
}
