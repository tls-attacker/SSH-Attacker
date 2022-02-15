/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import de.rub.nds.sshattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.sshattacker.core.crypto.ec.EllipticCurve;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum NamedGroup {
    SECT163K1("sect163k1", 163),
    SECT163R1("sect163r1", 163),
    SECT163R2("sect163r2", 163),
    SECT193R1("sect193r1", 193),
    SECT193R2("sect193r2", 193),
    SECT233K1("sect233k1", 233),
    SECT233R1("sect233r1", 233),
    SECT239K1("sect239k1", 239),
    SECT283K1("sect283k1", 283),
    SECT283R1("sect283r1", 283),
    SECT409K1("sect409k1", 409),
    SECT409R1("sect409r1", 409),
    SECT571K1("sect571k1", 571),
    SECT571R1("sect571r1", 571),
    SECP160K1("secp160k1", 160),
    SECP160R1("secp160r1", 160),
    SECP160R2("secp160r2", 150),
    SECP192K1("secp192k1", 192),
    SECP192R1("secp192r1", 192),
    SECP224K1("secp224k1", 224),
    SECP224R1("secp224r1", 224),
    SECP256K1("secp256k1", 256),
    SECP256R1("secp256r1", 256),
    SECP384R1("secp384r1", 384),
    SECP521R1("secp521r1", 521),
    BRAINPOOLP256R1("brainpoolp256r1", 256),
    BRAINPOOLP384R1("brainpoolp384r1", 384),
    BRAINPOOLP512R1("brainpoolp512r1", 512),
    ECDH_X25519("ecdh_X25519", 256),
    ECDH_X448("ecdh_X448", 448);

    private static final Logger LOGGER = LogManager.getLogger();

    public static final int LENGTH = 2;

    private String javaName;

    private final Integer coordinateSizeInBit;

    NamedGroup(String javaName, Integer coordinateSizeInBit) {
        this.javaName = javaName;
        this.coordinateSizeInBit = coordinateSizeInBit;
    }

    public static NamedGroup fromJavaName(String name) {
        if (name.equals("prime256v1")) {
            return SECP256R1;
        }
        for (NamedGroup group : values()) {
            if (group.getJavaName().equals(name)) {
                return group;
            }
        }
        return null;
    }

    public String getJavaName() {
        return javaName;
    }

    public void setJavaName(String javaName) {
        this.javaName = javaName;
    }

    private static Integer valueToInt(byte[] value) {
        if (value.length < 2) {
            LOGGER.warn("Could not convert NamedGroup. Returning null");
            return null;
        }
        return (value[0] & 0xff) << Bits.IN_A_BYTE | (value[1] & 0xff);
    }

    public static NamedGroup getNamedGroup(ECPublicKey publicKey) {
        for (NamedGroup group : getImplemented()) {
            // TODO: X25519 and X448 not supported for classic java curves
            if (group.isStandardCurve()) {
                try {
                    EllipticCurve tlsAttackerCurve = CurveFactory.getCurve(group);
                    if (publicKey
                                    .getParams()
                                    .getGenerator()
                                    .getAffineX()
                                    .equals(tlsAttackerCurve.getBasePoint().getFieldX().getData())
                            && publicKey
                                    .getParams()
                                    .getGenerator()
                                    .getAffineY()
                                    .equals(
                                            tlsAttackerCurve
                                                    .getBasePoint()
                                                    .getFieldY()
                                                    .getData())) {
                        return group;
                    }
                } catch (UnsupportedOperationException e) {
                    LOGGER.debug("Could not test " + group.name() + " not completely integrated");
                }
            }
        }
        return null;
    }

    public static NamedGroup getNamedGroup(ECPrivateKey privateKey) {
        for (NamedGroup group : getImplemented()) {
            // TODO: X25519 and X448 not supported for classic java curves
            if (group.isStandardCurve()) {
                try {
                    EllipticCurve tlsAttackerCurve = CurveFactory.getCurve(group);
                    if (privateKey
                                    .getParams()
                                    .getGenerator()
                                    .getAffineX()
                                    .equals(tlsAttackerCurve.getBasePoint().getFieldX().getData())
                            && privateKey
                                    .getParams()
                                    .getGenerator()
                                    .getAffineY()
                                    .equals(
                                            tlsAttackerCurve
                                                    .getBasePoint()
                                                    .getFieldY()
                                                    .getData())) {
                        return group;
                    }
                } catch (UnsupportedOperationException e) {
                    LOGGER.debug("Could not test " + group.name() + " not completely integrated");
                }
            }
        }
        return null;
    }

    public Integer getCoordinateSizeInBit() {
        return coordinateSizeInBit;
    }

    public boolean isStandardCurve() {
        return this != ECDH_X25519 && this != ECDH_X448;
    }

    @SuppressWarnings("BooleanMethodIsAlwaysInverted")
    public boolean isRFC7748Curve() {
        return this == ECDH_X25519 || this == ECDH_X448;
    }

    public static List<NamedGroup> getImplemented() {
        List<NamedGroup> list = new LinkedList<>();
        list.add(SECP160K1);
        list.add(SECP160R1);
        list.add(SECP160R2);
        list.add(SECP192K1);
        list.add(SECP192R1);
        list.add(SECP224K1);
        list.add(SECP224R1);
        list.add(SECP256K1);
        list.add(SECP256R1);
        list.add(SECP384R1);
        list.add(SECP521R1);
        list.add(SECT163K1);
        list.add(SECT163R1);
        list.add(SECT163R2);
        list.add(SECT193R1);
        list.add(SECT193R2);
        list.add(SECT233K1);
        list.add(SECT233R1);
        list.add(SECT239K1);
        list.add(SECT283K1);
        list.add(SECT283R1);
        list.add(SECT409K1);
        list.add(SECT409R1);
        list.add(SECT571K1);
        list.add(SECT571R1);
        list.add(ECDH_X25519);
        list.add(ECDH_X448);
        list.add(BRAINPOOLP256R1);
        list.add(BRAINPOOLP384R1);
        list.add(BRAINPOOLP512R1);
        return list;
    }
}
