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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.handler.Handler;
import de.rub.nds.sshattacker.core.protocol.preparator.DhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.core.protocol.serializer.DhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhKeyExchangeInitMessage extends Message<DhKeyExchangeInitMessage> {

    private ModifiableInteger publicKeyLength;
    private ModifiableBigInteger publicKey;

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public ModifiableBigInteger getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableBigInteger publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger publicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    @Override
    public Handler<DhKeyExchangeInitMessage> getHandler(SshContext context) {
        // TODO: Implement DHKeyExchangeInitMessage handler
        throw new NotImplementedException("DHKeyExchangeInitMessage::getHandler");
    }

    @Override
    public Serializer<DhKeyExchangeInitMessage> getSerializer() {
        return new DhKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public Preparator<DhKeyExchangeInitMessage> getPreparator(SshContext context) {
        return new DhKeyExchangeInitMessagePreparator(context, this);
    }

    @Override
    public String toCompactString() {
        return "DHKeyExchangeInitMessage";
    }
}
