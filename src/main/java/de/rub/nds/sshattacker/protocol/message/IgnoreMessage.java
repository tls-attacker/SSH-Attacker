/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.protocol.handler.IgnoreMessageHandler;
import de.rub.nds.sshattacker.protocol.preparator.IgnoreMessagePreparator;
import de.rub.nds.sshattacker.protocol.serializer.IgnoreMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class IgnoreMessage extends Message<IgnoreMessage> {

    private ModifiableString data;

    public ModifiableString getData() {
        return data;
    }

    public void setData(ModifiableString data) {
        this.data = data;
    }

    public void setData(String data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public IgnoreMessageHandler getHandler(SshContext context) {
        return new IgnoreMessageHandler(context);
    }

    @Override
    public IgnoreMessageSerializer getSerializer() {
        return new IgnoreMessageSerializer(this);
    }

    @Override
    public IgnoreMessagePreparator getPreparator(SshContext context) {
        return new IgnoreMessagePreparator(context, this);
    }
}
