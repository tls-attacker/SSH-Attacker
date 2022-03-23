/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.UnformattedByteArrayAdapter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.NamedGroup;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * A serializable elliptic curve private key for X curves (Curve 25519 and Curve 448) used in the
 * X25519 / X448 key exchange.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class XCurveEcPrivateKey extends CustomPrivateKey {

    private NamedGroup group;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] scalar;

    @SuppressWarnings("unused")
    private XCurveEcPrivateKey() {}

    public XCurveEcPrivateKey(byte[] scalar, NamedGroup group) {
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "XCurveEcPrivateKey does not support named group " + group);
        }
        if ((group == NamedGroup.CURVE25519 && scalar.length != CryptoConstants.X25519_POINT_SIZE)
                || group == NamedGroup.CURVE448
                        && scalar.length != CryptoConstants.X448_POINT_SIZE) {
            throw new IllegalArgumentException(
                    "Tried to instantiate a new XCurveEcPrivateKey with a mismatching scalar length");
        }
        this.group = group;
        this.scalar = scalar;
    }

    public NamedGroup getGroup() {
        return group;
    }

    public void setGroup(NamedGroup group) {
        this.group = group;
    }

    public byte[] getScalar() {
        return scalar;
    }

    public void setScalar(byte[] scalar) {
        this.scalar = scalar;
    }

    public PrivateKey toEdDsaKey() {
        try {
            KeyFactory keyFactory;
            PrivateKeyInfo privateKeyInfo;
            if (group == NamedGroup.CURVE25519) {
                keyFactory = KeyFactory.getInstance("Ed25519");
                privateKeyInfo =
                        new PrivateKeyInfo(
                                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                new DEROctetString(scalar));
            } else {
                keyFactory = KeyFactory.getInstance("Ed448");
                privateKeyInfo =
                        new PrivateKeyInfo(
                                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
                                new DEROctetString(scalar));
            }
            PKCS8EncodedKeySpec encodedKeySpec =
                    new PKCS8EncodedKeySpec(privateKeyInfo.getEncoded());
            return keyFactory.generatePrivate(encodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            return null;
        }
    }

    // Interface methods
    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "Octet";
    }

    @Override
    public byte[] getEncoded() {
        return scalar;
    }
}
