/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
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
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ActivateEncryptionAction extends ConnectionBoundAction {

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        Chooser chooser = context.getChooser();
        KeySet keySet = KeySetGenerator.generateKeySet(context);

        EncryptionAlgorithm outEnc = chooser.getSendEncryptionAlgorithm();
        MacAlgorithm outMac = chooser.getSendMacAlgorithm();
        context.getPacketLayer()
                .updateEncryptionCipher(
                        PacketCipherFactory.getPacketCipher(context, keySet, outEnc, outMac));

        EncryptionAlgorithm inEnc = chooser.getReceiveEncryptionAlgorithm();
        MacAlgorithm inMac = chooser.getReceiveMacAlgorithm();
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
