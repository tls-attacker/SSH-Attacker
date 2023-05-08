/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message.extension;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.UnknownExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnknownExtension extends AbstractExtension<UnknownExtension> {

    private ModifiableInteger valueLength;

    private ModifiableByteArray value;

    public UnknownExtension() {
        super();
    }

    public ModifiableInteger getValueLength() {
        return valueLength;
    }

    public void setValueLength(ModifiableInteger valueLength) {
        this.valueLength = valueLength;
    }

    public void setValueLength(int valueLength) {
        this.valueLength = ModifiableVariableFactory.safelySetValue(this.valueLength, valueLength);
    }

    public ModifiableByteArray getValue() {
        return value;
    }

    public void setValue(ModifiableByteArray value) {
        setValue(value, false);
    }

    public void setValue(byte[] value) {
        setValue(value, false);
    }

    public void setValue(ModifiableByteArray value, boolean adjustLengthField) {
        if (adjustLengthField) {
            setValueLength(value.getValue().length);
        }
        this.value = value;
    }

    public void setValue(byte[] value, boolean adjustLengthField) {
        if (adjustLengthField) {
            setValueLength(value.length);
        }
        this.value = ModifiableVariableFactory.safelySetValue(this.value, value);
    }

    @Override
    public UnknownExtensionHandler getHandler(SshContext context) {
        return new UnknownExtensionHandler(context, this);
    }
}
