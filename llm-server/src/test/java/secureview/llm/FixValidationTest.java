package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class FixValidationTest {

    private static final Verdict TP = new Verdict(Verdict.Result.TRUE_POSITIVE, 0.9, List.of(2), "r", null);
    private static final Finding JAVA_FINDING =
            new Finding("F", "A.java", 2, 2, "R", 89, "HIGH", "m", List.of("t"));
    private static final CodeContext JAVA = new CodeContext("A.java", 1, 3,
            List.of("public int find(String name) {", "  return run(name);", "}"), true, new TreeMap<>());
    private static final Finding C_FINDING =
            new Finding("F", "a.c", 2, 2, "R", 120, "HIGH", "m", List.of("t"));
    private static final CodeContext C = new CodeContext("a.c", 1, 3,
            List.of("void copy(char *d, const char *s) {", "  strcpy(d, s);", "}"), true, new TreeMap<>());

    private static String reply(String code) {
        return "{\"code\":\"" + code + "\",\"reason\":\"r\"}";
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(ints = {89, 79, 78, 22, 798, 120, 416, 476, 134, 190})
    void promptGivesCweSpecificFixMethod(int cwe) {
        Finding finding = new Finding("F", "A.java", 2, 2, "R", cwe, "HIGH", "m", List.of("t"));
        FakeLlm llm = new FakeLlm(reply("public int find(String name) { return safe(name); }"));

        new FixService(llm).propose(finding, JAVA, TP, null);

        assertTrue(llm.prompts.get(0).contains(FixService.METHODS.get(cwe)));
    }

    @Test
    void usesFunctionRangeFromManual() {
        FakeLlm llm = new FakeLlm(reply("public int find(String name) { return safe(name); }"));

        Fix fix = new FixService(llm).propose(JAVA_FINDING, JAVA, TP, null).orElseThrow();

        assertEquals(List.of(1, 3), fix.functionRange());
    }

    @Test
    void javaFixWithExtraMemberIsRetried() {
        FakeLlm llm = new FakeLlm(
                reply("private final Connection conn; public int find(String name) { return safe(name); }"),
                reply("public int find(String name) { return safe(name); }"));

        Fix fix = new FixService(llm).propose(JAVA_FINDING, JAVA, TP, null).orElseThrow();

        assertEquals(2, llm.prompts.size());
        assertTrue(llm.prompts.get(1).contains("함수 하나"));
        assertFalse(fix.code().contains("conn;"));
    }

    @Test
    void javaFixWithChangedSignatureIsRetried() {
        FakeLlm llm = new FakeLlm(
                reply("public int find(String name, int limit) { return safe(name); }"),
                reply("public int findSafe(String name) { return safe(name); }"));

        assertTrue(new FixService(llm).propose(JAVA_FINDING, JAVA, TP, null).isEmpty());
        assertTrue(llm.prompts.get(1).contains("선언"));
    }

    @Test
    void javaFixThatDoesNotParseIsRetried() {
        FakeLlm llm = new FakeLlm(reply("public int find(String name) { return safe(name; }"),
                reply("1| public int find(String name) { return safe(name); }"));

        assertTrue(new FixService(llm).propose(JAVA_FINDING, JAVA, TP, null).isEmpty());
    }

    @Test
    void cFixMustBeOneFunctionWithSameName() {
        String good = "void copy(char *d, const char *s) { strncpy(d, s, 8); }";
        assertTrue(new FixService(new FakeLlm(reply(good))).propose(C_FINDING, C, TP, null).isPresent());

        String renamed = "void copy2(char *d, const char *s) { strncpy(d, s, 8); }";
        assertTrue(new FixService(new FakeLlm(reply(renamed), reply(renamed))).propose(C_FINDING, C, TP, null).isEmpty());

        String extra = "int helper(void) { return 1; } " + good;
        assertTrue(new FixService(new FakeLlm(reply(extra), reply(extra))).propose(C_FINDING, C, TP, null).isEmpty());

        String broken = "void copy(char *d, const char *s) { strncpy(d, s, 8);";
        assertTrue(new FixService(new FakeLlm(reply(broken), reply(broken))).propose(C_FINDING, C, TP, null).isEmpty());
    }

    @Test
    void fragmentFixOnlyRejectsLineNumbers() {
        CodeContext fragment = new CodeContext("A.java", 1, 3, List.of("a", "b", "c"), false, new TreeMap<>());
        assertTrue(new FixService(new FakeLlm(reply("x = 1;"))).propose(JAVA_FINDING, fragment, TP, null).isPresent());

        FakeLlm llm = new FakeLlm(reply("1| x = 1;"), reply("x = 1;"));
        assertEquals("x = 1;", new FixService(llm).propose(JAVA_FINDING, fragment, TP, null).orElseThrow().code());
    }
}
