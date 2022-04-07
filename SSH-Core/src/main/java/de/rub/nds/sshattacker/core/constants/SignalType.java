/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

public enum SignalType {
    /*
     * Sources:
     * - https://datatracker.ietf.org/doc/html/rfc4254
     */
    SIGABRT("ABRT"),
    SIGALRM("ALRM"),
    SIGFPE("FPE"),
    SIGUP("UP"),
    SIGILL("ILL"),
    SIGINT("INT"),
    SIGKILL("KILL"),
    SIGPIPE("IPE"),
    SIGQUIT("QUIT"),
    SIGSEGV("SEGV"),
    SIGTERM("TERM"),
    SIGUSR1("USR1"),
    SIGUSR2("USR2");

    private final String name;

    SignalType(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return name;
    }
}
