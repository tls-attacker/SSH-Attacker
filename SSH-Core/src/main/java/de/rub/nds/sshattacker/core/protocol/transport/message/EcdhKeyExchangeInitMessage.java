/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.EcdhKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class EcdhKeyExchangeInitMessage extends SshMessage<EcdhKeyExchangeInitMessage> {

    private ModifiableInteger publicKeyLength;
    private ModifiableByteArray publicKey;

    public EcdhKeyExchangeInitMessage() {
        super(MessageIDConstant.SSH_MSG_KEX_ECDH_INIT);
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

    public ModifiableByteArray getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(ModifiableByteArray publicKey) {
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(byte[] publicKey) {
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(ModifiableByteArray publicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPublicKeyLength(publicKey.getValue().length);
        }
        this.publicKey = publicKey;
    }

    public void setPublicKey(byte[] publicKey, boolean adjustLengthField) {
        if (adjustLengthField) {
            setPublicKeyLength(publicKey.length);
        }
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
    }

    @Override
    public EcdhKeyExchangeInitMessageHandler getHandler(SshContext context) {
        return new EcdhKeyExchangeInitMessageHandler(context, this);
    }
}
