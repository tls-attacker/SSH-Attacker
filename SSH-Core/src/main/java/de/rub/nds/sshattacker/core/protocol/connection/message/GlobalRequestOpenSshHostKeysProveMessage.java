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
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.util.OpenSshHostKeyHelper;
import de.rub.nds.sshattacker.core.protocol.connection.handler.GlobalRequestOpenSshHostKeysProveMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.List;

public class GlobalRequestOpenSshHostKeysProveMessage
        extends GlobalRequestMessage<GlobalRequestOpenSshHostKeysProveMessage> {
    private ModifiableByteArray hostKeys;

    public ModifiableByteArray getHostKeys() {
        return hostKeys;
    }

    public void setHostKeys(ModifiableByteArray hostKeys) {
        this.hostKeys = hostKeys;
    }

    public void setHostKeys(byte[] hostKeys) {
        this.hostKeys = ModifiableVariableFactory.safelySetValue(this.hostKeys, hostKeys);
    }

    public void setHostKeys(List<SshPublicKey<?, ?>> hostKeys) {
        this.hostKeys =
                ModifiableVariableFactory.safelySetValue(
                        this.hostKeys, OpenSshHostKeyHelper.encodeKeys(hostKeys));
    }

    @Override
    public GlobalRequestOpenSshHostKeysProveMessageHandler getHandler(SshContext context) {
        return new GlobalRequestOpenSshHostKeysProveMessageHandler(context, this);
    }
}
