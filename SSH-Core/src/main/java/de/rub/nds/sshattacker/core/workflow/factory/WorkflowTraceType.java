/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.workflow.factory;

public enum WorkflowTraceType {
    KEX_INIT_ONLY,
    KEX_DH,
    KEX_ECDH,
    KEX_DH_GEX,
    KEX_RSA,
    KEX_HYBRID,
    KEX_DYNAMIC,
    AUTH_NONE,
    AUTH_PASSWORD,
    AUTH_KEYBOARD_INTERACTIVE,
    AUTH_PUBLICKEY,
    AUTH_DYNAMIC,
    FULL,
    SFTP_INIT,
    REQ_TCP_IP_FORWARD,
    MITM
}
