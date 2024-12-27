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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.transport.handler.extension.UnknownExtensionHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class UnknownExtension extends AbstractExtension<UnknownExtension> {

    private ModifiableInteger valueLength;

    private ModifiableByteArray value;

    public UnknownExtension() {
        super();
    }

    public UnknownExtension(UnknownExtension other) {
        super(other);
        valueLength = other.valueLength != null ? other.valueLength.createCopy() : null;
        value = other.value != null ? other.value.createCopy() : null;
    }

    @Override
    public UnknownExtension createCopy() {
        return new UnknownExtension(this);
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
        this.value = ModifiableVariableFactory.safelySetValue(this.value, value);
        if (adjustLengthField) {
            setValueLength(this.value.getValue().length);
        }
    }

    public void setSoftlyValue(byte[] value, boolean adjustLengthField, Config config) {
        if (this.value == null || this.value.getOriginalValue() == null) {
            this.value = ModifiableVariableFactory.safelySetValue(this.value, value);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || valueLength == null
                    || valueLength.getOriginalValue() == null) {
                setValueLength(this.value.getValue().length);
            }
        }
    }

    @Override
    public UnknownExtensionHandler getHandler(SshContext context) {
        return new UnknownExtensionHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        UnknownExtensionHandler.PREPARATOR.prepare(this, chooser);
    }
}
