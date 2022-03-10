/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.task;

/**
 * Interface for Tasks. Tasks can be executed and return true/false if the execution was
 * successful/failed
 */
public interface ITask {

    boolean execute();
}
