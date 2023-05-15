/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.common.ModifiableVariableHolder;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.AbstractExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public abstract class AbstractExtension<E extends AbstractExtension<E>>
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

    public abstract AbstractExtensionHandler<E> getHandler(SshContext context);
}
