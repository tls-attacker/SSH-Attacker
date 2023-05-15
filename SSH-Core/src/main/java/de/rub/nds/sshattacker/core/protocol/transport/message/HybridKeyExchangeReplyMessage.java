/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeReplyMessage extends SshMessage<HybridKeyExchangeReplyMessage>
        implements HostKeyMessage, ExchangeHashSignatureMessage {

    private ModifiableInteger hostKeyBytesLength;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger publicKeyLength;
    private ModifiableByteArray publicKey;

    private ModifiableInteger combinedKeyShareLength;
    private ModifiableByteArray combinedKeyShare;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    @Override
    public ModifiableInteger getHostKeyBytesLength() {
        return hostKeyBytesLength;
    }

    @Override
    public void setHostKeyBytesLength(ModifiableInteger hostKeyBytesLength) {
        this.hostKeyBytesLength = hostKeyBytesLength;
    }

    @Override
    public void setHostKeyBytesLength(int hostKeyBytesLength) {
        this.hostKeyBytesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hostKeyBytesLength, hostKeyBytesLength);
    }

    @Override
    public ModifiableByteArray getHostKeyBytes() {
        return hostKeyBytes;
    }

    @Override
    public SshPublicKey<?, ?> getHostKey() {
        return PublicKeyHelper.parse(hostKeyBytes.getValue());
    }

    @Override
    public void setHostKeyBytes(ModifiableByteArray hostKeyBytes) {
        setHostKeyBytes(hostKeyBytes, false);
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes) {
        setHostKeyBytes(hostKeyBytes, false);
    }

    @Override
    public void setHostKeyBytes(ModifiableByteArray hostKeyBytes, boolean adjustLengthField) {
        this.hostKeyBytes = hostKeyBytes;
        if (adjustLengthField) {
            setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
        }
    }

    @Override
    public void setHostKeyBytes(byte[] hostKeyBytes, boolean adjustLengthField) {
        this.hostKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
        if (adjustLengthField) {
            setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
        }
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

    public void setPublicKey(byte[] publicKey) {
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(ModifiableByteArray publicKey, boolean adjustLengthField) {
        this.publicKey = publicKey;
        if (adjustLengthField) {
            setPublicKeyLength(this.publicKey.getValue().length);
        }
    }

    public void setPublicKey(byte[] publicKey, boolean adjustLengthField) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
        if (adjustLengthField) {
            setPublicKeyLength(this.publicKey.getValue().length);
        }
    }

    public ModifiableInteger getCombinedKeyShareLength() {
        return combinedKeyShareLength;
    }

    public void setCombinedKeyShareLength(ModifiableInteger combinedKeyShareLength) {
        this.combinedKeyShareLength = combinedKeyShareLength;
    }

    public void setCiphertextLength(int ciphertextLength) {
        combinedKeyShareLength =
                ModifiableVariableFactory.safelySetValue(combinedKeyShareLength, ciphertextLength);
    }

    public ModifiableByteArray getCombinedKeyShare() {
        return combinedKeyShare;
    }

    public void setCombinedKeyShare(byte[] combinedKeyShare) {
        setCiphertext(combinedKeyShare, false);
    }

    public void setCiphertext(ModifiableByteArray ciphertext, boolean adjustLengthField) {
        combinedKeyShare = ciphertext;
        if (adjustLengthField) {
            setCiphertextLength(combinedKeyShare.getValue().length);
        }
    }

    public void setCiphertext(byte[] ciphertext, boolean adjustLengthField) {
        combinedKeyShare = ModifiableVariableFactory.safelySetValue(combinedKeyShare, ciphertext);
        if (adjustLengthField) {
            setCiphertextLength(combinedKeyShare.getValue().length);
        }
    }

    @Override
    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    @Override
    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    @Override
    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    @Override
    public ModifiableByteArray getSignature() {
        return signature;
    }

    @Override
    public void setSignature(ModifiableByteArray signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        this.signature = signature;
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public void setSignature(byte[] signature, boolean adjustLengthField) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public HybridKeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new HybridKeyExchangeReplyMessageHandler(context, this);
    }
}
