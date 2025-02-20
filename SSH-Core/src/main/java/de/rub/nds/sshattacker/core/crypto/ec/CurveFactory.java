/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ec;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;

public final class CurveFactory {

    /**
     * Returns a named elliptic curve.
     *
     * @param name The name of the curve, that should be returned.
     * @return EllipticCurve for the provided NamedGroup
     */
    public static EllipticCurve getCurve(NamedEcGroup name) {
        return switch (name) {
            case BRAINPOOLP256R1 -> new EllipticCurveBrainpoolP256R1();
            case BRAINPOOLP384R1 -> new EllipticCurveBrainpoolP384R1();
            case BRAINPOOLP512R1 -> new EllipticCurveBrainpoolP512R1();
            case SECP160K1 -> new EllipticCurveSECP160K1();
            case SECP160R1 -> new EllipticCurveSECP160R1();
            case SECP160R2 -> new EllipticCurveSECP160R2();
            case SECP192K1 -> new EllipticCurveSECP192K1();
            case SECP192R1 -> new EllipticCurveSECP192R1();
            case SECP224K1 -> new EllipticCurveSECP224K1();
            case SECP224R1 -> new EllipticCurveSECP224R1();
            case SECP256K1 -> new EllipticCurveSECP256K1();
            case SECP256R1 -> new EllipticCurveSECP256R1();
            case SECP384R1 -> new EllipticCurveSECP384R1();
            case SECP521R1 -> new EllipticCurveSECP521R1();
            case SECT163K1 -> new EllipticCurveSECT163K1();
            case SECT163R1 -> new EllipticCurveSECT163R1();
            case SECT163R2 -> new EllipticCurveSECT163R2();
            case SECT193R1 -> new EllipticCurveSECT193R1();
            case SECT193R2 -> new EllipticCurveSECT193R2();
            case SECT233K1 -> new EllipticCurveSECT233K1();
            case SECT233R1 -> new EllipticCurveSECT233R1();
            case SECT239K1 -> new EllipticCurveSECT239K1();
            case SECT283K1 -> new EllipticCurveSECT283K1();
            case SECT283R1 -> new EllipticCurveSECT283R1();
            case SECT409K1 -> new EllipticCurveSECT409K1();
            case SECT409R1 -> new EllipticCurveSECT409R1();
            case SECT571K1 -> new EllipticCurveSECT571K1();
            case SECT571R1 -> new EllipticCurveSECT571R1();
            default ->
                    throw new UnsupportedOperationException(
                            "The provided group '" + name + "' is not supported by this method.");
        };
    }

    private CurveFactory() {
        super();
    }
}
