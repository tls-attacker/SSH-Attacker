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
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Handler;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.DhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.DhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.common.Serializer;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.math.BigInteger;

public class DhKeyExchangeInitMessage extends Message<DhKeyExchangeInitMessage> {

    private ModifiableInteger publicKeyLength;
    private ModifiableBigInteger publicKey;

    public DhKeyExchangeInitMessage() {
        super(MessageIDConstant.SSH_MSG_KEXDH_INIT);
    }

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
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(BigInteger publicKey) {
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(ModifiableBigInteger publicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPublicKeyLength(publicKey.getValue().toByteArray().length);
        }
        this.publicKey = publicKey;
    }

    public void setPublicKey(BigInteger publicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPublicKeyLength(publicKey.toByteArray().length);
        }
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
}
