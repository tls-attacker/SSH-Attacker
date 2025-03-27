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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.protocol.authentication.handler.UserAuthPkOkMessageHandler;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class UserAuthPkOkMessage extends SshMessage<UserAuthPkOkMessage> {

    private ModifiableInteger publicKeyAlgorithmNameLength;
    private ModifiableString publicKeyAlgorithmName;
    private ModifiableInteger publicKeyBlobLength;
    private ModifiableByteArray publicKeyBlob;

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

    @Override
    public UserAuthPkOkMessageHandler getHandler(SshContext context) {
        return new UserAuthPkOkMessageHandler(context, this);
    }
}
