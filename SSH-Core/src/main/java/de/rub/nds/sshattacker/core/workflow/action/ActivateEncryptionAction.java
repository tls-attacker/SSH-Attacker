/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;

public class ActivateEncryptionAction extends ConnectionBoundAction {

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        KeySet keySet = KeySetGenerator.generateKeySet(context);
        EncryptionAlgorithm outEnc =
                context.isClient()
                        ? context.getCipherAlgorithmClientToServer()
                                .orElseThrow(WorkflowExecutionException::new)
                        : context.getCipherAlgorithmServerToClient()
                                .orElseThrow(WorkflowExecutionException::new);
        EncryptionAlgorithm inEnc =
                context.isClient()
                        ? context.getCipherAlgorithmServerToClient()
                                .orElseThrow(WorkflowExecutionException::new)
                        : context.getCipherAlgorithmClientToServer()
                                .orElseThrow(WorkflowExecutionException::new);
        MacAlgorithm outMac =
                context.isClient()
                        ? context.getMacAlgorithmClientToServer()
                                .orElseThrow(WorkflowExecutionException::new)
                        : context.getMacAlgorithmServerToClient()
                                .orElseThrow(WorkflowExecutionException::new);
        MacAlgorithm inMac =
                context.isClient()
                        ? context.getMacAlgorithmServerToClient()
                                .orElseThrow(WorkflowExecutionException::new)
                        : context.getMacAlgorithmClientToServer()
                                .orElseThrow(WorkflowExecutionException::new);

        context.getPacketLayer()
                .updateEncryptionCipher(
                        PacketCipherFactory.getPacketCipher(context, keySet, outEnc, outMac));
        context.getPacketLayer()
                .updateDecryptionCipher(
                        PacketCipherFactory.getPacketCipher(context, keySet, inEnc, inMac));
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
