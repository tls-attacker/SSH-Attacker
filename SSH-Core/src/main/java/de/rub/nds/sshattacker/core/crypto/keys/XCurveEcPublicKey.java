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
import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

/**
 * A serializable elliptic curve public key for X curves (Curve 25519 and Curve 448) used in the
 * X25519 / X448 key exchange.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class XCurveEcPublicKey extends CustomPublicKey {

    private NamedEcGroup group;

    @XmlJavaTypeAdapter(UnformattedByteArrayAdapter.class)
    private byte[] coordinate;

    @SuppressWarnings("unused")
    public XCurveEcPublicKey() {}

    public XCurveEcPublicKey(byte[] coordinate, NamedEcGroup group) {
        if (!group.isRFC7748Curve()) {
            throw new IllegalArgumentException(
                    "XCurveEcPublicKey does not support named group " + group);
        }
        if ((group == NamedEcGroup.CURVE25519
                        && coordinate.length != CryptoConstants.X25519_POINT_SIZE)
                || group == NamedEcGroup.CURVE448
                        && coordinate.length != CryptoConstants.X448_POINT_SIZE) {
            throw new IllegalArgumentException(
                    "Tried to instantiate a new XCurveEcPublicKey with a mismatching coordinate length");
        }
        this.group = group;
        this.coordinate = coordinate;
    }

    public NamedEcGroup getGroup() {
        return group;
    }

    public void setGroup(NamedEcGroup group) {
        this.group = group;
    }

    public byte[] getCoordinate() {
        return coordinate;
    }

    public void setCoordinate(byte[] coordinate) {
        this.coordinate = coordinate;
    }

    public PublicKey toEdDsaKey() {
        try {
            KeyFactory keyFactory;
            SubjectPublicKeyInfo publicKeyInfo;
            if (group == NamedEcGroup.CURVE25519) {
                keyFactory = KeyFactory.getInstance("Ed25519");
                publicKeyInfo =
                        new SubjectPublicKeyInfo(
                                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                                coordinate);
            } else {
                keyFactory = KeyFactory.getInstance("Ed448");
                publicKeyInfo =
                        new SubjectPublicKeyInfo(
                                new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed448),
                                coordinate);
            }
            PKCS8EncodedKeySpec encodedKeySpec =
                    new PKCS8EncodedKeySpec(publicKeyInfo.getEncoded());
            return keyFactory.generatePublic(encodedKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            return null;
        }
    }

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
        return coordinate;
    }
}
