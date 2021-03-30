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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.serializer.EcdhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.handler.Handler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeInitMessage extends Message<EcdhKeyExchangeInitMessage> {

    private ModifiableInteger publicKeyLength;
    private ModifiableByteArray publicKey;

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength = ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public ModifiableByteArray getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableByteArray publicKey) {
        this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    @Override
    public String toCompactString() {
        return "ECDHKeyExchangeInitMessage";
    }

    @Override
    public Handler<EcdhKeyExchangeInitMessage> getHandler(SshContext context) {
        return new Handler<EcdhKeyExchangeInitMessage>(context) {
            @Override
            public void handle(EcdhKeyExchangeInitMessage msg) {
                // not needed as Client
            }
        };
    }

    @Override
    public EcdhKeyExchangeInitMessageSerializer getSerializer() {
        return new EcdhKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public EcdhKeyExchangeInitMessagePreparator getPreparator(SshContext context) {
        return new EcdhKeyExchangeInitMessagePreparator(context, this);
    }

}
