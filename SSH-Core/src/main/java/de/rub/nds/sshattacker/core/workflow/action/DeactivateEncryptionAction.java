/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.CipherMode;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;

public class DeactivateEncryptionAction extends ConnectionBoundAction {

    public DeactivateEncryptionAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public DeactivateEncryptionAction(String connectionAlias) {
        super(connectionAlias);
    }

    public DeactivateEncryptionAction(DeactivateEncryptionAction other) {
        super(other);
    }

    @Override
    public DeactivateEncryptionAction createCopy() {
        return new DeactivateEncryptionAction(this);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        context.getPacketLayer()
                .updateEncryptionCipher(
                        PacketCipherFactory.getNoneCipher(context, CipherMode.ENCRYPT));
        context.getPacketLayer()
                .updateDecryptionCipher(
                        PacketCipherFactory.getNoneCipher(context, CipherMode.DECRYPT));
        setExecuted(true);
    }

    @Override
    public void reset(boolean resetModifiableVariables) {
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
