/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.constants.CompressionAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChangeCompressionAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    private CompressionAlgorithm previousAlgorithm;
    private CompressionAlgorithm targetAlgorithm;

    public ChangeCompressionAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ChangeCompressionAction(String connectionAlias) {
        super(connectionAlias);
    }

    public ChangeCompressionAction(CompressionAlgorithm targetAlgorithm) {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
        this.targetAlgorithm = targetAlgorithm;
    }

    public ChangeCompressionAction(String connectionAlias, CompressionAlgorithm targetAlgorithm) {
        super(connectionAlias);
        this.targetAlgorithm = targetAlgorithm;
    }

    public void setTargetAlgorithm(CompressionAlgorithm targetAlgorithm) {
        this.targetAlgorithm = targetAlgorithm;
    }

    public CompressionAlgorithm getPreviousAlgorithm() {
        return previousAlgorithm;
    }

    public CompressionAlgorithm getTargetAlgorithm() {
        return targetAlgorithm;
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        previousAlgorithm = context.getPacketLayer().getCompressor().getCompressionAlgorithm();
        context.getPacketLayer().updateCompressionAlgorithm(targetAlgorithm);
        context.getPacketLayer().updateDecompressionAlgorithm(targetAlgorithm);
        LOGGER.info(
                "Changed active compression algorithm from {} to {}",
                previousAlgorithm,
                targetAlgorithm);
        setExecuted(true);
    }

    @Override
    public void reset() {
        previousAlgorithm = null;
        setExecuted(null);
    }

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }
}
