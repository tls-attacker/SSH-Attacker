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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeReplyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

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

    public HybridKeyExchangeReplyMessage() {
        super();
    }

    public HybridKeyExchangeReplyMessage(HybridKeyExchangeReplyMessage other) {
        super(other);
        hostKeyBytesLength =
                other.hostKeyBytesLength != null ? other.hostKeyBytesLength.createCopy() : null;
        hostKeyBytes = other.hostKeyBytes != null ? other.hostKeyBytes.createCopy() : null;
        publicKeyLength = other.publicKeyLength != null ? other.publicKeyLength.createCopy() : null;
        publicKey = other.publicKey != null ? other.publicKey.createCopy() : null;
        combinedKeyShareLength =
                other.combinedKeyShareLength != null
                        ? other.combinedKeyShareLength.createCopy()
                        : null;
        combinedKeyShare =
                other.combinedKeyShare != null ? other.combinedKeyShare.createCopy() : null;
        signatureLength = other.signatureLength != null ? other.signatureLength.createCopy() : null;
        signature = other.signature != null ? other.signature.createCopy() : null;
    }

    @Override
    public HybridKeyExchangeReplyMessage createCopy() {
        return new HybridKeyExchangeReplyMessage(this);
    }

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

    public void setSoftlyHostKeyBytes(
            byte[] hostKeyBytes, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.hostKeyBytes == null
                || this.hostKeyBytes.getOriginalValue() == null) {
            this.hostKeyBytes =
                    ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || hostKeyBytesLength == null
                    || hostKeyBytesLength.getOriginalValue() == null) {
                setHostKeyBytesLength(this.hostKeyBytes.getValue().length);
            }
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

    public void setSoftlyPublicKey(byte[] publicKey, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.publicKey == null
                || this.publicKey.getOriginalValue() == null) {
            this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || publicKeyLength == null
                    || publicKeyLength.getOriginalValue() == null) {
                setPublicKeyLength(this.publicKey.getValue().length);
            }
        }
    }

    public ModifiableInteger getCombinedKeyShareLength() {
        return combinedKeyShareLength;
    }

    public void setCombinedKeyShareLength(ModifiableInteger combinedKeyShareLength) {
        this.combinedKeyShareLength = combinedKeyShareLength;
    }

    public void setCombinedKeyShareLength(int ciphertextLength) {
        combinedKeyShareLength =
                ModifiableVariableFactory.safelySetValue(combinedKeyShareLength, ciphertextLength);
    }

    public ModifiableByteArray getCombinedKeyShare() {
        return combinedKeyShare;
    }

    public void setCombinedKeyShare(byte[] combinedKeyShare) {
        setCombinedKeyShare(combinedKeyShare, false);
    }

    public void setCombinedKeyShare(ModifiableByteArray ciphertext, boolean adjustLengthField) {
        combinedKeyShare = ciphertext;
        if (adjustLengthField) {
            setCombinedKeyShareLength(combinedKeyShare.getValue().length);
        }
    }

    public void setCombinedKeyShare(byte[] combinedKeyShare, boolean adjustLengthField) {
        this.combinedKeyShare =
                ModifiableVariableFactory.safelySetValue(this.combinedKeyShare, combinedKeyShare);
        if (adjustLengthField) {
            setCombinedKeyShareLength(this.combinedKeyShare.getValue().length);
        }
    }

    public void setSoftlyCombinedKeyShare(
            byte[] combinedKeyShare, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.combinedKeyShare == null
                || this.combinedKeyShare.getOriginalValue() == null) {
            this.combinedKeyShare =
                    ModifiableVariableFactory.safelySetValue(
                            this.combinedKeyShare, combinedKeyShare);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || combinedKeyShareLength == null
                    || combinedKeyShareLength.getOriginalValue() == null) {
                setCombinedKeyShareLength(this.combinedKeyShare.getValue().length);
            }
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

    public void setSoftlySignature(byte[] signature, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.signature == null
                || this.signature.getOriginalValue() == null) {
            this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || signatureLength == null
                    || signatureLength.getOriginalValue() == null) {
                setSignatureLength(this.signature.getValue().length);
            }
        }
    }

    @Override
    public HybridKeyExchangeReplyMessageHandler getHandler(SshContext context) {
        return new HybridKeyExchangeReplyMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        HybridKeyExchangeReplyMessageHandler.PREPARATOR.prepare(this, chooser);
    }
}
