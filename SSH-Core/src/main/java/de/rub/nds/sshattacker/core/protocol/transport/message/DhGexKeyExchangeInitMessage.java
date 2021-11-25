/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.biginteger.ModifiableBigInteger;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.DhGexKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.math.BigInteger;

public class DhGexKeyExchangeInitMessage extends SshMessage<DhGexKeyExchangeInitMessage> {
    private ModifiableInteger publicKeyLength;
    private ModifiableBigInteger publicKey;

    public DhGexKeyExchangeInitMessage() {
        super(MessageIDConstant.SSH_MSG_KEX_DH_GEX_INIT);
    }

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength =
                ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
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
    public DhGexKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new DhGexKeyExchangeInitMessageHandler(context, this);
    }
}
