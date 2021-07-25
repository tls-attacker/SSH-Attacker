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
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhGexKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhGexKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhGexKeyExchangeInitMessage extends Message<DhGexKeyExchangeInitMessage> {

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
    public Handler<DhGexKeyExchangeInitMessage> getHandler(SshContext context) {
        // TODO: Implement DhGexKeyExchangeInitMessage handler
        throw new NotImplementedException("DhGexKeyExchangeInitMessage::getHandler");
    }

    @Override
    public Serializer<DhGexKeyExchangeInitMessage> getSerializer() {
        return new DhGexKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public Preparator<DhGexKeyExchangeInitMessage> getPreparator(SshContext context) {
        return new DhGexKeyExchangeInitMessagePreparator(context, this);
    }

    @Override
    public String toCompactString() {
        return "DHGexKeyExchangeInitMessage";
    }
}
