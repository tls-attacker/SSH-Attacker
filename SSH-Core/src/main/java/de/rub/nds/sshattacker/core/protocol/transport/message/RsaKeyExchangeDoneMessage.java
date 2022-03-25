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
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeDoneMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeDoneMessage extends SshMessage<RsaKeyExchangeDoneMessage> {

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public RsaKeyExchangeDoneMessage() {
        super(MessageIDConstant.SSH_MSG_KEXRSA_DONE);
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

    public ModifiableByteArray getSignature() {
        return signature;
    }

    public void setSignature(ModifiableByteArray signature) {
        this.setSignature(signature, false);
    }

    public void setSignature(byte[] signature) {
        this.setSignature(signature, false);
    }

    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setSignatureLength(signature.getValue().length);
        }
        this.signature = signature;
    }

    public void setSignature(byte[] signature, boolean adjustLengthField) {
        if (adjustLengthField) {
            this.setSignatureLength(signature.length);
        }
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
    }

    @Override
    public SshMessageHandler<RsaKeyExchangeDoneMessage> getHandler(SshContext context) {
        return new RsaKeyExchangeDoneMessageHandler(context, this);
    }
}
