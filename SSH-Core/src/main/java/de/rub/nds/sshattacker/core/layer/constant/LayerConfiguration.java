/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.layer.constant;

/**
 * Pre-defined configurations for the Layer Stack. E.g., DTLS would add the UDP-, Record-,
 * Fragmentation-, and Message- Layer to the LayerStack. Custom LayerStack have to be created
 * manually.
 */
public enum LayerConfiguration {
    SSHv1,
    SSHv2;
    /*    TLS,
    DTLS,
    QUIC,
    OPEN_VPN,

    STARTTLS,
    HTTPS,
    SSL2; */
}
