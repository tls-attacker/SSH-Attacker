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
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.packet.cipher.PacketCipherFactory;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ActivateEncryptionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    public ActivateEncryptionAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ActivateEncryptionAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ActivateEncryptionAction(ActivateEncryptionAction other) {
        super(other);
    }

    @Override
    public ActivateEncryptionAction createCopy() {
        return new ActivateEncryptionAction(this);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        Chooser chooser = context.getChooser();
        Optional<KeySet> keySet = context.getKeySet();
        if (keySet.isEmpty()) {
            LOGGER.error(
                    "Unable to activate encryption, there is no key set available in the context");
            return;
        }

        EncryptionAlgorithm outEnc = chooser.getSendEncryptionAlgorithm();
        MacAlgorithm outMac = chooser.getSendMacAlgorithm();
        context.getPacketLayer()
                .updateEncryptionCipher(
                        PacketCipherFactory.getPacketCipher(
                                context, keySet.get(), outEnc, outMac, CipherMode.ENCRYPT));

        EncryptionAlgorithm inEnc = chooser.getReceiveEncryptionAlgorithm();
        MacAlgorithm inMac = chooser.getReceiveMacAlgorithm();
        context.getPacketLayer()
                .updateDecryptionCipher(
                        PacketCipherFactory.getPacketCipher(
                                context, keySet.get(), inEnc, inMac, CipherMode.DECRYPT));

        if (context.getStrictKeyExchangeEnabled().orElse(false)) {
            LOGGER.info("Resetting sequence numbers because of strict key exchange");
            context.setReadSequenceNumber(0);
            context.setWriteSequenceNumber(0);
        }
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

    @Override
    public String toString() {
        if (isExecuted()) {
            return "ActivateEncryptionAction";
        } else {
            return "ActivateEncryptionAction (not executed)";
        }
    }
}
