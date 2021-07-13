/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.handler.Handler;
import de.rub.nds.sshattacker.core.protocol.preparator.DhGexKeyExchangeOldRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.core.protocol.serializer.DhGexKeyExchangeOldRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeOldRequestMessage extends Message<DhGexKeyExchangeOldRequestMessage> {

    private ModifiableInteger preferredGroupSize;

    public ModifiableInteger getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(ModifiableInteger preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize = ModifiableVariableFactory.safelySetValue(this.preferredGroupSize, preferredGroupSize);
    }

    @Override
    public Handler<DhGexKeyExchangeOldRequestMessage> getHandler(SshContext context) {
        // TODO: Implement handler for DhGexKeyExchangeRequestMessage
        throw new NotImplementedException("DhGexKeyExchangeRequestMessage::getHandler");
    }

    @Override
    public Serializer<DhGexKeyExchangeOldRequestMessage> getSerializer() {
        return new DhGexKeyExchangeOldRequestMessageSerializer(this);
    }

    @Override
    public Preparator<DhGexKeyExchangeOldRequestMessage> getPreparator(SshContext context) {
        return new DhGexKeyExchangeOldRequestMessagePreparator(context, this);
    }

    @Override
    public String toCompactString() {
        return "DHGexKeyExchangeOldRequestMessage";
    }
}
