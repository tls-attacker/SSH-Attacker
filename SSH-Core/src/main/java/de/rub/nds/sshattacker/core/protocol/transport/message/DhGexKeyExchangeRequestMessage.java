/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeRequestMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeRequestMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DhGexKeyExchangeRequestMessage extends Message<DhGexKeyExchangeRequestMessage> {

    private ModifiableInteger minimalGroupSize;
    private ModifiableInteger preferredGroupSize;
    private ModifiableInteger maximalGroupSize;

    public ModifiableInteger getMinimalGroupSize() {
        return minimalGroupSize;
    }

    public void setMinimalGroupSize(ModifiableInteger minimalGroupSize) {
        this.minimalGroupSize = minimalGroupSize;
    }

    public void setMinimalGroupSize(int minimalGroupSize) {
        this.minimalGroupSize = ModifiableVariableFactory.safelySetValue(this.minimalGroupSize, minimalGroupSize);
    }

    public ModifiableInteger getPreferredGroupSize() {
        return preferredGroupSize;
    }

    public void setPreferredGroupSize(ModifiableInteger preferredGroupSize) {
        this.preferredGroupSize = preferredGroupSize;
    }

    public void setPreferredGroupSize(int preferredGroupSize) {
        this.preferredGroupSize = ModifiableVariableFactory.safelySetValue(this.preferredGroupSize, preferredGroupSize);
    }

    public ModifiableInteger getMaximalGroupSize() {
        return maximalGroupSize;
    }

    public void setMaximalGroupSize(ModifiableInteger maximalGroupSize) {
        this.maximalGroupSize = maximalGroupSize;
    }

    public void setMaximalGroupSize(int maximalGroupSize) {
        this.maximalGroupSize = ModifiableVariableFactory.safelySetValue(this.maximalGroupSize, maximalGroupSize);
    }

    @Override
    public Handler<DhGexKeyExchangeRequestMessage> getHandler(SshContext context) {
        // TODO: Implement handler for DhGexKeyExchangeRequestMessage
        throw new NotImplementedException("DhGexKeyExchangeRequestMessage::getHandler");
    }

    @Override
    public Serializer<DhGexKeyExchangeRequestMessage> getSerializer() {
        return new DhGexKeyExchangeRequestMessageSerializer(this);
    }

    @Override
    public Preparator<DhGexKeyExchangeRequestMessage> getPreparator(SshContext context) {
        return new DhGexKeyExchangeRequestMessagePreparator(context, this);
    }

    @Override
    public String toCompactString() {
        return "DHGexKeyExchangeRequestMessage";
    }
}
