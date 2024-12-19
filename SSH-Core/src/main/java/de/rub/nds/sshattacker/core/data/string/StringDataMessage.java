/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.data.string;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.data.DataMessage;
import de.rub.nds.sshattacker.core.state.SshContext;

public class StringDataMessage extends DataMessage<StringDataMessage> {

    private ModifiableString data;

    public StringDataMessage() {
        super();
    }

    public StringDataMessage(StringDataMessage other) {
        super(other);
        data = other.data != null ? other.data.createCopy() : null;
    }

    @Override
    public StringDataMessage createCopy() {
        return new StringDataMessage(this);
    }

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString data) {
        this.data = data;
    }

    public void setData(String data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    public void setSoftlyData(String data) {
        if (this.data == null || this.data.getOriginalValue() == null) {
            this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
        }
    }

    @Override
    public String toCompactString() {
        return getClass().getSimpleName();
    }

    @Override
    public StringDataMessageHandler getHandler(SshContext context) {
        return new StringDataMessageHandler(context, this);
    }
}
