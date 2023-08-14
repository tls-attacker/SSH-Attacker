/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestHostKeysProveSuccessMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;

public class GlobalRequestHostKeysProveSuccessMessage
        extends ChannelMessage<GlobalRequestHostKeysProveSuccessMessage> {

    // ToDo maybe it makes sense to make GLobalRequestSuccessMessage abstract
    // and heritate from it, thus default GlobalRequestSuccessMessage needs to be implemented as
    // subclass
    private ModifiableInteger hostKeySignaturesLength;
    private ModifiableByteArray hostKeySignatures;

    public ModifiableInteger getHostKeySignaturesLength() {
        return hostKeySignaturesLength;
    }

    public void setHostKeySignaturesLength(ModifiableInteger hostKeySignaturesLength) {
        this.hostKeySignaturesLength = hostKeySignaturesLength;
    }

    public void setHostKeySignaturesLength(int hostKeySignaturesLength) {
        this.hostKeySignaturesLength =
                ModifiableVariableFactory.safelySetValue(
                        this.hostKeySignaturesLength, hostKeySignaturesLength);
    }

    public void setHostKeySignatures(ModifiableByteArray hostKeySignatures) {
        this.hostKeySignatures = hostKeySignatures;
    }

    public ModifiableByteArray getHostKeySignatures() {
        return hostKeySignatures;
    }

    public void setHostKeySignatures(byte[] hostKeySignatures) {
        this.hostKeySignatures =
                ModifiableVariableFactory.safelySetValue(this.hostKeySignatures, hostKeySignatures);
    }

    public void setHostKeySignatures(List<SshPublicKey<?, ?>> hostKeySignatures) {
        this.hostKeySignatures =
                ModifiableVariableFactory.safelySetValue(
                        this.hostKeySignatures, OpenSshHostKeyHelper.encodeKeys(hostKeySignatures));
    }

    public void setHostKeySignatures(
            ModifiableByteArray hostKeySignatures, boolean adjustLengthField) {
        this.hostKeySignatures = hostKeySignatures;
        if (adjustLengthField) {
            setHostKeySignaturesLength(this.hostKeySignatures.getValue().length);
        }
    }

    public void setHostKeySignatures(byte[] hostKeySignatures, boolean adjustLengthField) {
        this.hostKeySignatures =
                ModifiableVariableFactory.safelySetValue(this.hostKeySignatures, hostKeySignatures);
        if (adjustLengthField) {
            setHostKeySignaturesLength(this.hostKeySignatures.getValue().length);
        }
    }

    @Override
    public GlobalRequestHostKeysProveSuccessMessageHandler getHandler(SshContext context) {
        return new GlobalRequestHostKeysProveSuccessMessageHandler(context, this);
    }
}
