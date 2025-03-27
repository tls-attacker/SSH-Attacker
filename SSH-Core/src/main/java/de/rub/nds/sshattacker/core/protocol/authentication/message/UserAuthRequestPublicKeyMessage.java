/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthRequestPublicKeyMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public class UserAuthRequestPublicKeyMessage
        extends UserAuthRequestMessage<UserAuthRequestPublicKeyMessage> {

    private ModifiableByte includesSignature;
    private ModifiableInteger publicKeyAlgorithmNameLength;
    private ModifiableString publicKeyAlgorithmName;
    private ModifiableInteger publicKeyBlobLength;
    private ModifiableByteArray publicKeyBlob;
    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public ModifiableByte getIncludesSignature() {
        return includesSignature;
    }

    public void setIncludesSignature(ModifiableByte includesSignature) {
        this.includesSignature = includesSignature;
    }

    public void setIncludesSignature(byte includesSignature) {
        this.includesSignature =
                ModifiableVariableFactory.safelySetValue(this.includesSignature, includesSignature);
    }

    public void setIncludesSignature(boolean includesSignature) {
        setIncludesSignature(Converter.booleanToByte(includesSignature));
    }

    public ModifiableInteger getPublicKeyAlgorithmNameLength() {
        return publicKeyAlgorithmNameLength;
    }

    public void setPublicKeyAlgorithmNameLength(ModifiableInteger publicKeyAlgorithmNameLength) {
        this.publicKeyAlgorithmNameLength = publicKeyAlgorithmNameLength;
    }

    public void setPublicKeyAlgorithmNameLength(int publicKeyAlgorithmNameLength) {
        this.publicKeyAlgorithmNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicKeyAlgorithmNameLength, publicKeyAlgorithmNameLength);
    }

    public ModifiableString getPublicKeyAlgorithmName() {
        return publicKeyAlgorithmName;
    }

    public void setPublicKeyAlgorithmName(ModifiableString publicKeyAlgorithmName) {
        setPublicKeyAlgorithmName(publicKeyAlgorithmName, false);
    }

    public void setPublicKeyAlgorithmName(String publicKeyAlgorithmName) {
        setPublicKeyAlgorithmName(publicKeyAlgorithmName, false);
    }

    public void setPublicKeyAlgorithmName(
            ModifiableString publicKeyAlgorithmName, boolean adjustLengthField) {
        this.publicKeyAlgorithmName = publicKeyAlgorithmName;
        if (adjustLengthField) {
            setPublicKeyAlgorithmNameLength(
                    this.publicKeyAlgorithmName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setPublicKeyAlgorithmName(
            String publicKeyAlgorithmName, boolean adjustLengthField) {
        this.publicKeyAlgorithmName =
                ModifiableVariableFactory.safelySetValue(
                        this.publicKeyAlgorithmName, publicKeyAlgorithmName);
        if (adjustLengthField) {
            setPublicKeyAlgorithmNameLength(
                    this.publicKeyAlgorithmName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public ModifiableInteger getPublicKeyBlobLength() {
        return publicKeyBlobLength;
    }

    public void setPublicKeyBlobLength(ModifiableInteger publicKeyBlobLength) {
        this.publicKeyBlobLength = publicKeyBlobLength;
    }

    public void setPublicKeyBlobLength(int publicKeyBlobLength) {
        this.publicKeyBlobLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicKeyBlobLength, publicKeyBlobLength);
    }

    public ModifiableByteArray getPublicKeyBlob() {
        return publicKeyBlob;
    }

    public void setPublicKeyBlob(ModifiableByteArray publicKeyBlob) {
        setPublicKeyBlob(publicKeyBlob, false);
    }

    public void setPublicKeyBlob(byte[] publicKeyBlob) {
        setPublicKeyBlob(publicKeyBlob, false);
    }

    public void setPublicKeyBlob(ModifiableByteArray publicKeyBlob, boolean adjustLengthField) {
        this.publicKeyBlob = publicKeyBlob;
        if (adjustLengthField) {
            setPublicKeyBlobLength(this.publicKeyBlob.getValue().length);
        }
    }

    public void setPublicKeyBlob(byte[] publicKeyBlob, boolean adjustLengthField) {
        this.publicKeyBlob =
                ModifiableVariableFactory.safelySetValue(this.publicKeyBlob, publicKeyBlob);
        if (adjustLengthField) {
            setPublicKeyBlobLength(this.publicKeyBlob.getValue().length);
        }
    }

    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    public void setSignature(ModifiableByteArray signature) {
        setSignature(signature, false);
    }

    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        this.signature = signature;
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    public void setSignature(byte[] signature, boolean adjustLengthField) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    public ModifiableByteArray getSignature() {
        return signature;
    }

    @Override
    public UserAuthRequestPublicKeyMessageHandler getHandler(SshContext context) {
        return new UserAuthRequestPublicKeyMessageHandler(context, this);
    }
}
