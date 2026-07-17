package org.pqcpki.algo;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AlgorithmsTest {

    @Test
    @DisplayName("ids are unique and every one resolves back to its spec")
    void idsAreUniqueAndResolvable() {
        Set<String> ids = new HashSet<>(Algorithms.ids());
        assertEquals(Algorithms.ids().size(), ids.size(), "duplicate algorithm id");
        for (String id : ids) {
            assertEquals(id, Algorithms.byId(id).id());
        }
    }

    @Test
    @DisplayName("the set spans every family the study compares")
    void coversEveryFamily() {
        Set<Family> families = new HashSet<>();
        Algorithms.all().forEach(a -> families.add(a.family()));
        for (Family f : Family.values()) {
            assertTrue(families.contains(f), "no algorithm registered for family " + f);
        }
    }

    @Test
    @DisplayName("classical specs carry a key-generation parameter; PQC specs do not")
    void keyGenParametersAreConsistent() {
        for (AlgorithmSpec spec : Algorithms.all()) {
            if (spec.isClassical()) {
                assertFalse(spec.keyGenParameter() == null || spec.keyGenParameter().isBlank(),
                        spec.id() + " is classical but has no key-generation parameter");
            } else {
                assertEquals(null, spec.keyGenParameter(),
                        spec.id() + " is PQC/composite and should need no key-generation parameter");
            }
        }
    }

    @Test
    @DisplayName("an unknown id is rejected with a helpful message")
    void unknownIdRejected() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Algorithms.byId("no-such-algo"));
        assertTrue(e.getMessage().contains("known:"), "error should list the known ids");
    }
}
