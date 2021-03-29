package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.EcdhKeyExchangeInitMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.EcdhKeyExchangeInitMessageSerializer;
import de.rub.nds.sshattacker.protocol.serializer.Serializer;
import de.rub.nds.sshattacker.state.SshContext;

public class EcdhKeyExchangeInitMessage extends Message {

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
    public Handler getHandler(SshContext context) {
        return new Handler(context) {
            @Override
            public void handle(Object msg) {
                // not needed as Client
            }
        };
    }

    @Override
    public Serializer getSerializer() {
        return new EcdhKeyExchangeInitMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new EcdhKeyExchangeInitMessagePreparator(context, this);
    }

}
