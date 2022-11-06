/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.core;

import static org.junit.Assert.assertTrue;

import cc.redberry.rings.poly.univar.UnivariateDivision;
import cc.redberry.rings.poly.univar.UnivariatePolynomialZ64;
import de.rub.nds.sshattacker.core.crypto.ntrup.sntrup.util.Encoding;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

public class Rounded {
    private SntrupParameterSet set;
    private UnivariatePolynomialZ64 rounded;
    private UnivariatePolynomialZ64 mod;

    private Rounded(SntrupParameterSet set, UnivariatePolynomialZ64 rounded) {
        this.set = set;
        this.mod = generateMod(set);
        this.rounded = rounded;
    }

    public Rounded(SntrupParameterSet set, long[] coefficients) {
        assertTrue("coefficients are not rounded", is_rounded(set, coefficients));
        this.set = set;
        this.mod = generateMod(set);
        this.rounded =
                UnivariateDivision.remainder(
                        UnivariatePolynomialZ64.create(coefficients), mod, false);
    }

    public SntrupParameterSet getSet() {
        return set;
    }

    private static UnivariatePolynomialZ64 generateMod(SntrupParameterSet set) {
        return UnivariatePolynomialZ64.parse("x^" + set.getP() + "-x-1");
    }

    public static Rounded round(RQ rq) {
        long[] rounded = round(rq.stream());
        long error =
                Arrays.stream(rounded)
                        .filter(
                                c ->
                                        c > (rq.getSet().getQ() + 1) / 2
                                                || c < -(rq.getSet().getQ() + 1) / 2)
                        .peek(c -> System.out.println(c))
                        .findFirst()
                        .orElse(0);
        assertTrue(
                "Coefficients have to be between (-(q-1)/2 and (q-1)/2, but is " + error,
                error == 0);
        return new Rounded(rq.getSet(), UnivariatePolynomialZ64.create(rounded));
    }

    public static boolean is_rounded(SntrupParameterSet set, long[] coefficients) {
        return !Arrays.stream(coefficients)
                .filter(c -> c % 3 != 0 || c < -((set.getQ() + 1) / 2) || c > (set.getQ() + 1) / 2)
                .findFirst()
                .isPresent();
    }

    private static long[] round(LongStream coefficients) {
        return coefficients.map(l -> 3 * (Math.round(l / 3.0f))).toArray();
    }

    public LongStream stream() {
        return rounded.stream().map(c -> (c > (set.getQ() + 1) / 2 ? c - set.getQ() : c));
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

        assertTrue(
                "0 > R[i] for some i", r.stream().filter(i -> i < 0).findFirst().isEmpty() == true);
        assertTrue(
                "R[i] > M[i] for some i",
                IntStream.range(0, set.getP())
                                .filter(i -> r.get(i) > m.get(i))
                                .findFirst()
                                .isPresent()
                        == false);

        ArrayList<Integer> encdodedCoefficients = Encoding.encode(r, m);
        byte[] res = new byte[encdodedCoefficients.size()];
        for (int i = 0; i < encdodedCoefficients.size(); i++) {
            res[i] = (byte) (encdodedCoefficients.get(i).intValue());
        }
        return res;
    }

    public static Rounded decode(SntrupParameterSet set, byte[] encodedRounded) {
        ArrayList<Integer> r = new ArrayList<>();
        for (int i = 0; i < encodedRounded.length; i++) {
            r.add((int) encodedRounded[i] & 0xff);
        }

        ArrayList<Integer> m =
                IntStream.range(0, set.getP())
                        .map(i -> (set.getQ() - 1) / 3 + 1)
                        .boxed()
                        .collect(Collectors.toCollection(ArrayList::new));

        assertTrue(
                "0 > R[i] for some i", r.stream().filter(i -> i < 0).findFirst().isEmpty() == true);
        assertTrue(
                "R[i] > M[i] for some i",
                IntStream.range(0, set.getP())
                                .filter(i -> r.get(i) > m.get(i))
                                .findFirst()
                                .isPresent()
                        == false);

        ArrayList<Integer> coef = Encoding.decode(r, m);
        return new Rounded(
                set, coef.stream().mapToLong(l -> 3 * l - (set.getQ() - 1) / 2).toArray());
    }

    @Override
    public String toString() {
        return rounded.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((rounded == null) ? 0 : rounded.hashCode());
        result = prime * result + ((set == null) ? 0 : set.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null) return false;
        if (getClass() != obj.getClass()) return false;
        Rounded other = (Rounded) obj;
        if (rounded == null) {
            if (other.rounded != null) return false;
        } else if (!rounded.equals(other.rounded)) return false;
        if (set != other.set) return false;
        return true;
    }
}
