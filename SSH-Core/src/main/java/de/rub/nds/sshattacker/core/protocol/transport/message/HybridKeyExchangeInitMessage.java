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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class HybridKeyExchangeInitMessage extends SshMessage<HybridKeyExchangeInitMessage> {

    private ModifiableInteger publicValuesLength;
    private ModifiableByteArray publicValues;

    private ModifiableByteArray classicalPublicKey;
    private ModifiableByteArray postQuantumPublicKey;

    public ModifiableInteger getPublicValuesLength() {
        return publicValuesLength;
    }

    public void setPublicValuesLength(ModifiableInteger publicValuesLength) {
        this.publicValuesLength = publicValuesLength;
    }

    public void setPublicValuesLength(int publicValuesLength) {
        this.publicValuesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.publicValuesLength, publicValuesLength);
    }

    public ModifiableByteArray getPublicValues() {
        return publicValues;
    }

    public void setPublicValues(ModifiableByteArray publicValues) {
        this.publicValues = publicValues;
    }

    public void setPublicValues(byte[] publicValues) {
        this.publicValues =
                ModifiableVariableFactory.safelySetValue(this.publicValues, publicValues);
    }

    public void setPublicValues(ModifiableByteArray publicValues, boolean adjustLengthField) {
        this.publicValues = publicValues;
        if (adjustLengthField) {
            setPublicValuesLength(this.publicValues.getValue().length);
        }
    }

    public void setPublicValues(byte[] publicValues, boolean adjustLengthField) {
        this.publicValues =
                ModifiableVariableFactory.safelySetValue(this.publicValues, publicValues);
        if (adjustLengthField) {
            setPublicValuesLength(this.publicValues.getValue().length);
        }
    }

    public ModifiableByteArray getClassicalPublicKey() {
        return classicalPublicKey;
    }

    public void setClassicalPublicKey(ModifiableByteArray classicalPublicKey) {
        this.classicalPublicKey = classicalPublicKey;
    }

    public void setClassicalPublicKey(byte[] classicalPublicKey) {
        this.classicalPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.classicalPublicKey, classicalPublicKey);
    }

    public ModifiableByteArray getPostQuantumPublicKey() {
        return postQuantumPublicKey;
    }

    public void setPostQuantumPublicKey(ModifiableByteArray postQuantumPublicKey) {
        this.postQuantumPublicKey = postQuantumPublicKey;
    }

    public void setPostQuantumPublicKey(byte[] postQuantumPublicKey) {
        this.postQuantumPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.postQuantumPublicKey, postQuantumPublicKey);
    }

    @Override
    public SshMessageHandler<HybridKeyExchangeInitMessage> getHandler(SshContext context) {
        return new HybridKeyExchangeInitMessageHandler(context, this);
    }
}
