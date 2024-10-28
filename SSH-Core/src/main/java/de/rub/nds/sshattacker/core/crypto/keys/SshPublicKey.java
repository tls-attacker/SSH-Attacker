/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.keys;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import jakarta.xml.bind.annotation.*;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * This class represents a public key with its corresponding public key algorithm as used throughout
 * the SSH protocol. A corresponding private key may be present in case of a local key.
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class SshPublicKey<PUBLIC extends CustomPublicKey, PRIVATE extends CustomPrivateKey>
        implements Serializable {

    private PublicKeyFormat publicKeyFormat;

    @XmlElements({
        @XmlElement(name = "dhPublicKey", type = CustomDhPublicKey.class),
        @XmlElement(name = "dsaPublicKey", type = CustomDsaPublicKey.class),
        @XmlElement(name = "ecPublicKey", type = CustomEcPublicKey.class),
        @XmlElement(name = "rsaPublicKey", type = CustomRsaPublicKey.class),
        @XmlElement(name = "xCurvePublicKey", type = XCurveEcPublicKey.class),
        @XmlElement(name = "certDsaPublicKey", type = CustomCertDsaPublicKey.class),
        @XmlElement(name = "certEcdsaPublicKey", type = CustomCertEcdsaPublicKey.class),
        @XmlElement(name = "certRsaPublicKey", type = CustomCertRsaPublicKey.class),
        @XmlElement(name = "certXCurvePublicKey", type = CustomCertXCurvePublicKey.class),
        @XmlElement(name = "x509DsaPublicKey", type = CustomX509DsaPublicKey.class),
        @XmlElement(name = "x509EcdsaPublicKey", type = CustomX509EcdsaPublicKey.class),
        @XmlElement(name = "x509RsaPublicKey", type = CustomX509RsaPublicKey.class),
        @XmlElement(name = "x509XCurvePublicKey", type = CustomX509XCurvePublicKey.class)
    })
    private PUBLIC publicKey;

    @XmlElements({
        @XmlElement(name = "dhPrivateKey", type = CustomDhPrivateKey.class),
        @XmlElement(name = "dsaPrivateKey", type = CustomDsaPrivateKey.class),
        @XmlElement(name = "ecPrivateKey", type = CustomEcPrivateKey.class),
        @XmlElement(name = "rsaPrivateKey", type = CustomRsaPrivateKey.class),
        @XmlElement(name = "xCurvePrivateKey", type = XCurveEcPrivateKey.class)
    })
    private PRIVATE privateKey;

    protected SshPublicKey() {
        super();
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, CustomKeyPair<PRIVATE, PUBLIC> keyPair) {
        this(publicKeyFormat, keyPair.getPublicKey(), keyPair.getPrivateKey());
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, PUBLIC publicKey) {
        this(publicKeyFormat, publicKey, null);
    }

    public SshPublicKey(PublicKeyFormat publicKeyFormat, PUBLIC publicKey, PRIVATE privateKey) {
        super();
        if (publicKeyFormat == null || publicKey == null) {
            throw new IllegalArgumentException(
                    "Unable to construct SshPublicKey with public key algorithm or public key being null");
        }
        this.publicKeyFormat = publicKeyFormat;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PublicKeyFormat getPublicKeyFormat() {
        return publicKeyFormat;
    }

    public PUBLIC getPublicKey() {
        return publicKey;
    }

    public int getKeyStrength() {
        if (publicKey instanceof CustomDsaPublicKey) {
            return ((CustomDsaPublicKey) publicKey).getParams().getP().bitLength();
        } else if (publicKey instanceof CustomEcPublicKey) {
            return ((CustomEcPublicKey) publicKey).getGroup().getCoordinateSizeInBit();
        } else if (publicKey instanceof CustomRsaPublicKey) {
            return ((CustomRsaPublicKey) publicKey).getModulus().bitLength();
        } else if (publicKey instanceof CustomDhPublicKey) {
            return ((CustomDhPublicKey) publicKey).getParams().getP().bitLength();
        } else if (publicKey instanceof XCurveEcPublicKey) {
            return ((XCurveEcPublicKey) publicKey).getGroup().getCoordinateSizeInBit();
        } else {
            throw new UnsupportedOperationException(
                    "Unsupported public key type: " + publicKey.getClass().getSimpleName());
        }
    }

    public byte[] getEncoded() {
        return PublicKeyHelper.encode(this);
    }

    public byte[] getFingerprint(FingerprintType algorithm) {
        return computeFingerprint(algorithm);
    }

    public String getEncodedFingerprint(FingerprintType type, FingerprintEncoding encoding) {
        byte[] fingerprint = computeFingerprint(type);
        switch (encoding) {
            case HEX:
                return ArrayConverter.bytesToHexString(fingerprint);
            case BASE64:
                return Base64.getEncoder().encodeToString(fingerprint);
            case OPENSSH:
                return type
                        + ":"
                        + Base64.getEncoder().encodeToString(fingerprint).replace("=", "");
        }
        return ArrayConverter.bytesToHexString(fingerprint);
    }

    private byte[] computeFingerprint(FingerprintType type) {
        try {
            String hashAlgorithm = type.toString().replace("SHA", "SHA-");
            MessageDigest digest = MessageDigest.getInstance(hashAlgorithm);
            byte[] encodedPublicKey = getEncoded();
            return digest.digest(encodedPublicKey);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Unable to compute fingerprint", e);
        }
    }

    public Optional<PRIVATE> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    public String toString() {
        return String.format(
                "SshPublicKey[%s,%s]",
                publicKeyFormat.toString(), getPrivateKey().map(key -> "private").orElse("public"));
    }

    public enum FingerprintType {
        SHA1,
        SHA256
    }

    public enum FingerprintEncoding {
        HEX,
        BASE64,
        OPENSSH
    }
}
