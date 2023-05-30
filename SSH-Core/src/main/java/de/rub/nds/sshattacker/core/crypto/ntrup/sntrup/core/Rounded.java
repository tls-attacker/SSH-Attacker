/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.*;

import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZ64;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.util.Encoding;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

@SuppressWarnings("StandardVariableNames")
public class Rounded {
    private final SntrupParameterSet set;
    private final UnivariatePolynomialZ64 rounded;
    private final UnivariatePolynomialZ64 mod;

    private Rounded(SntrupParameterSet set, UnivariatePolynomialZ64 rounded) {
        super();
        this.set = set;
        mod = generateMod(set);
        this.rounded = rounded;
    }

    public Rounded(SntrupParameterSet set, long[] coefficients) {
        super();
        assertTrue(is_rounded(set, coefficients));
        this.set = set;
        mod = generateMod(set);
        rounded =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZ64.create(coefficients), mod, true);
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    private static UnivariatePolynomialZ64 generateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
    }

    public static Rounded round(RQ rq) {
        long[] rounded = round(rq.stream());
        assertFalse(
                Arrays.stream(rounded)
                        .filter(
                                c ->
                                        c > (rq.getSet().getQ() + 1) / 2
                                                || c < -(rq.getSet().getQ() + 1) / 2)
                        .findFirst()
                        .isPresent());
        return new Rounded(rq.getSet(), UnivariatePolynomialZ64.create(rounded));
    }

    public static boolean is_rounded(SntrupParameterSet set, long[] coefficients) {
        return Arrays.stream(coefficients)
                .filter(c -> c % 3 != 0 || c < -((set.getQ() + 1) / 2) || c > (set.getQ() + 1) / 2)
                .findFirst()
                .isEmpty();
    }

    private static long[] round(LongStream coefficients) {
        return coefficients.map(l -> 3L * Math.round(l / 3.0f)).toArray();
    }

    public LongStream stream() {
        return rounded.stream().map(c -> c > (set.getQ() + 1) / 2 ? c - set.getQ() : c);
    }

    public byte[] encode() {
        ArrayList<Integer> r =
                rounded.stream()
                        .mapToInt(l -> Math.toIntExact(l + (set.getQ() - 1) / 2) / 3)
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        ArrayList<Integer> m =
                IntStream.range(0, r.size())
                        .map(i -> (set.getQ() - 1) / 3 + 1)
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertTrue(r.stream().filter(i -> i < 0).findFirst().isEmpty());
        assertFalse(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent());

        ArrayList<Integer> encdodedCoefficients = Encoding.encode(r, m);
        byte[] res = new byte[encdodedCoefficients.size()];
        for (int i = 0; i < encdodedCoefficients.size(); i++) {
            res[i] = (byte) encdodedCoefficients.get(i).intValue();
        }
        return res;
    }

    // old encoding, used for SNTRUP4591761
    public byte[] encode_old() {
        int q61 = (set.getQ() - 1) / 6;
        ArrayList<Integer> r =
                rounded.stream()
                        .mapToInt(l -> Math.toIntExact(q61 + l / 3))
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));
        for (int i = 0; i < (-set.getP() + set.getP() * 6) % 6; i++) {
            r.add(0);
        }
        return Arrays.copyOfRange(Encoding.seq2byte(r, 1536, 3, 4), 0, 1015);
    }

    public static Rounded decode(SntrupParameterSet set, byte[] encodedRounded) {
        ArrayList<Integer> r = new ArrayList<>();
        for (byte b : encodedRounded) {
            r.add((int) b & 0xff);
        }

        ArrayList<Integer> m =
                IntStream.range(0, set.getP())
                        .map(i -> (set.getQ() - 1) / 3 + 1)
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertTrue(r.stream().filter(i -> i < 0).findFirst().isEmpty());
        assertFalse(
                IntStream.range(0, set.getP())
                        .filter(i -> r.get(i) > m.get(i))
                        .findFirst()
                        .isPresent());

        ArrayList<Integer> coef = Encoding.decode(r, m);
        return new Rounded(
                set, coef.stream().mapToLong(l -> 3L * l - (set.getQ() - 1) / 2).toArray());
    }

    public static Rounded decode_old(SntrupParameterSet set, byte[] encodedRounded) {
        int q61 = (set.getQ() - 1) / 6;
        ArrayList<BigInteger> coef = Encoding.byte2seq(encodedRounded, 1536, 3, 4);
        return new Rounded(
                set,
                coef.stream()
                        .limit(set.getP())
                        .mapToLong(l -> 3 * (l.longValue() % (q61 * 2 + 1) - q61))
                        .toArray());
    }

    @Override
    public String toString() {
        return rounded.toString();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        Rounded rounded1 = (Rounded) obj;
        return set == rounded1.set && Objects.equals(rounded, rounded1.rounded);
    }

    @Override
    public int hashCode() {
        return Objects.hash(set, rounded);
    }
}
