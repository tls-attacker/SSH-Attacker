/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.action;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.sshattacker.core.connection.AliasedConnection;
import de.rub.nds.sshattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.state.State;
import jakarta.xml.bind.annotation.XmlAttribute;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ModifySqnAction extends ConnectionBoundAction {

    private static final Logger LOGGER = LogManager.getLogger();

    protected VariableModification<Integer> modification;

    @XmlAttribute protected SqnType type;

    public ModifySqnAction() {
        super(AliasedConnection.DEFAULT_CONNECTION_ALIAS);
    }

    public ModifySqnAction(String connectionAlias) {
        super(connectionAlias);
    }

    @Override
    public void execute(State state) throws WorkflowExecutionException {
        SshContext context = state.getSshContext(getConnectionAlias());
        if (type == SqnType.READ) {
            LOGGER.info("Setting read sequence number modification to {}", modification);
            context.getReadSequenceNumber().setModification(modification);
        } else if (type == SqnType.WRITE) {
            LOGGER.info("Setting write sequence number modification to {}", modification);
            context.getWriteSequenceNumber().setModification(modification);
        } else {
            LOGGER.error("Unknown sequence number type");
        }
    }

    @Override
    public void reset() {}

    @Override
    public boolean executedAsPlanned() {
        return isExecuted();
    }

    public enum SqnType {
        READ,
        WRITE
    }
}
