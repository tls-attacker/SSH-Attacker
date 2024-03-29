/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.attacks.pkcs1.oracles;

import de.rub.nds.sshattacker.attacks.pkcs1.OracleException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/** Oracle template for Bleichenbacher/Manger like attacks. */
public abstract class Pkcs1Oracle {

    protected long numberOfQueries;

    protected int blockSize;

    protected RSAPublicKey publicKey;

    /** Indicates if the oracle accepts plaintext (for testing) or if it is a real oracle */
    @SuppressWarnings("FieldMayBeStatic")
    protected final boolean plaintextOracle = false;

    protected double averageTimeforRequest;
    protected double averageTimeforRequestInnerOracle;
    protected double averageTimeforRequestOuterOracle;

    /**
     * Gets the block size of the encryption algorithm.
     *
     * @return Block size
     */
    public int getBlockSize() {
        return blockSize;
    }

    /**
     * Gets the total number of queries performed by this oracle.
     *
     * @return Number of queries
     */
    public long getNumberOfQueries() {
        return numberOfQueries;
    }

    /**
     * Gets the public key of this oracle.
     *
     * @return Public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Checks for PKCS conformity - 00 maskedSeed maskedDataBlock
     *
     * @param msg Encrypted message to check for conformity
     * @return True if PKCS conforming, else false
     */
    public abstract boolean checkPKCSConformity(byte[] msg) throws OracleException;

    public boolean[] checkDoublePKCSConformity(final byte[] msg) throws OracleException {
        return new boolean[] {false, false};
    }

    /**
     * Returns true if the oracle is a plaintext oracle (does not decrypt the data received)
     *
     * @return isPlaintextOracle
     */
    public boolean isPlaintextOracle() {
        return plaintextOracle;
    }

    /** */
    public void resetNumberOfQueries() {
        numberOfQueries = 0;
    }
}
