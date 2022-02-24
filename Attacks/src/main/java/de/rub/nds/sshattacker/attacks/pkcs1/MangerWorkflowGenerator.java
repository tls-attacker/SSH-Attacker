/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangeSecretMessage;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;

/** */
public class MangerWorkflowGenerator {

    /**
     * @param sshConfig
     * @param encryptedSecretMessage
     * @return
     */
    public static WorkflowTrace generateWorkflow(Config sshConfig, byte[] encryptedSecretMessage) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(sshConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.START_KEYEXCHANGE, RunningModeType.CLIENT);
        trace.addSshAction(new ReceiveAction(new RsaKeyExchangePubkeyMessage()));
        RsaKeyExchangeSecretMessage secretMessage = new RsaKeyExchangeSecretMessage();
        ModifiableByteArray encryptedSecret = new ModifiableByteArray();
        encryptedSecret.setModification(
                ByteArrayModificationFactory.explicitValue(encryptedSecretMessage));
        secretMessage.setEncryptedSecret(encryptedSecret, true);
        trace.addSshAction(new SendAction(secretMessage));
        trace.addSshAction(new ReceiveAction());
        return trace;
    }

    private MangerWorkflowGenerator() {}
}
