package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

/** SQL에 들어가는 값이 함수 안에서 상수로만 정해지는지 코드로 판정한다. 예시는 OWASP Benchmark의 안전·진짜 사례를 줄인 것. */
class ConstantSqlTest {

    /** doPost 안에서 body 다음 줄이 SQL 호출이 되도록 파일을 만든다. after는 doPost 뒤에 붙는 메서드·클래스. */
    private static String source(String[] body, String... after) {
        List<String> lines = new ArrayList<>();
        lines.add("public class A {");
        lines.add("  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {");
        lines.add("    String param = request.getParameter(\"x\");");
        lines.addAll(List.of(body));
        lines.add("    statement.executeQuery(sql);");
        lines.add("  }");
        lines.addAll(List.of(after));
        lines.add("}");
        return String.join("\n", lines);
    }

    /** SQL 호출 줄 번호 */
    private static int sink(String[] body) {
        return 4 + body.length;
    }

    private static boolean constant(String... body) {
        return ConstantArgs.isConstant(source(body), sink(body));
    }

    /** 같은 파일의 final 필드는 컴파일 때 값이 정해진다. */
    @Test
    void finalFieldOfSameFileIsConstant() {
        String[] body = {"String sql = \"SELECT * FROM \" + TABLE + \" WHERE id = \" + LIMIT;"};
        assertTrue(ConstantArgs.isConstant(source(body, "  private static final String TABLE = \"users\";",
                "  private final int LIMIT = 10;"), sink(body)));
    }

    @Test
    void nonFinalOrUnknownFieldIsNotConstant() {
        String[] body = {"String sql = \"SELECT * FROM \" + table;"};
        assertFalse(ConstantArgs.isConstant(source(body, "  private static String table = \"users\";"), sink(body)));
        assertFalse(ConstantArgs.isConstant(source(body, "  private final String table = System.getenv(\"T\");"), sink(body)));
        assertFalse(ConstantArgs.isConstant(source(body), sink(body)));
    }

    /** 지역 변수가 같은 이름의 필드를 가리면 지역 변수 값을 쓴다. */
    @Test
    void localVariableShadowsFinalField() {
        String[] body = {"String TABLE = param;", "String sql = \"SELECT * FROM \" + TABLE;"};
        assertFalse(ConstantArgs.isConstant(source(body, "  private static final String TABLE = \"users\";"), sink(body)));
    }

    @Test
    void literalQueryIsConstant() {
        assertTrue(constant("String sql = \"SELECT * FROM U WHERE N='foo'\";"));
    }

    @Test
    void concatenatedParameterIsNotConstant() {
        assertFalse(constant("String sql = \"SELECT * FROM U WHERE N='\" + param + \"'\";"));
    }

    @Test
    void alwaysTrueBranchDiscardsInput() {
        assertTrue(constant(
                "String bar;",
                "int num = 86;",
                "if ((7 * 42) - num > 200) bar = \"This_should_always_happen\";",
                "else bar = param;",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void alwaysFalseBranchKeepsInput() {
        assertFalse(constant(
                "String bar;",
                "int num = 106;",
                "if ((7 * 18) + num > 200) bar = param;",
                "else bar = \"This should never happen\";",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void listAfterRemovingInputGivesConstant() {
        assertTrue(constant(
                "java.util.List<String> valuesList = new java.util.ArrayList<String>();",
                "valuesList.add(\"safe\");",
                "valuesList.add(param);",
                "valuesList.add(\"moresafe\");",
                "valuesList.remove(0);",
                "String bar = valuesList.get(1);",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void listGettingInputIsNotConstant() {
        assertFalse(constant(
                "java.util.List<String> valuesList = new java.util.ArrayList<String>();",
                "valuesList.add(\"safe\");",
                "valuesList.add(param);",
                "valuesList.add(\"moresafe\");",
                "valuesList.remove(0);",
                "String bar = valuesList.get(0);",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void mapSafeKeyIsConstantButInputKeyIsNot() {
        String[] safe = {
                "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();",
                "map.put(\"keyA\", \"a-Value\");",
                "map.put(\"keyB\", param);",
                "map.put(\"keyC\", \"another-Value\");",
                "String bar = (String) map.get(\"keyA\");",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"};
        assertTrue(constant(safe));
        safe[4] = "String bar = (String) map.get(\"keyB\");";
        assertFalse(constant(safe));
    }

    @Test
    void constantSwitchTakesOneCase() {
        String[] body = {
                "String bar;",
                "String guess = \"ABC\";",
                "char switchTarget = guess.charAt(1);",
                "switch (switchTarget) {",
                "    case 'A': bar = param; break;",
                "    case 'B': bar = \"bobs_your_uncle\"; break;",
                "    default: bar = param; break;",
                "}",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"};
        assertTrue(constant(body));
        body[2] = "char switchTarget = guess.charAt(0);";
        assertFalse(constant(body));
    }

    @Test
    void unknownMethodResultIsNotConstant() {
        assertFalse(constant(
                "String bar = thing.doSomething(\"fixed\");",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void stringBuilderWithInputIsNotConstant() {
        assertFalse(constant(
                "StringBuilder sb = new StringBuilder(\"SELECT * FROM U WHERE N='\");",
                "sb.append(param);",
                "String sql = sb.toString();"));
    }

    @Test
    void collectionPassedToUnknownMethodIsNotConstant() {
        assertFalse(constant(
                "java.util.List<String> list = new java.util.ArrayList<String>();",
                "list.add(\"safe\");",
                "helper.fill(list, param);",
                "String sql = \"SELECT * FROM U WHERE N='\" + list.get(0) + \"'\";"));
    }

    @Test
    void loopAssigningInputIsNotConstant() {
        assertFalse(constant(
                "String bar = \"safe\";",
                "for (String v : request.getParameterValues(\"y\")) { bar = v; }",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }


    private static final String[] CALLS_HELPER = {
            "String bar = doSomething(request, param);",
            "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"};

    @Test
    void helperMethodInSameFileIsFollowed() {
        String src = source(CALLS_HELPER,
                "  private static String doSomething(HttpServletRequest request, String param) {",
                "    String bar;",
                "    int num = 86;",
                "    if ((7 * 42) - num > 200) bar = \"This_should_always_happen\";",
                "    else bar = param;",
                "    return bar;",
                "  }");
        assertTrue(ConstantArgs.isConstant(src, sink(CALLS_HELPER)));
    }

    @Test
    void helperReturningInputIsNotConstant() {
        String src = source(CALLS_HELPER,
                "  private static String doSomething(HttpServletRequest request, String param) {",
                "    String bar = \"safe\";",
                "    if (param != null) bar = param;",
                "    return bar;",
                "  }");
        assertFalse(ConstantArgs.isConstant(src, sink(CALLS_HELPER)));
    }

    @Test
    void innerClassHelperIsFollowed() {
        String[] body = {
                "String bar = new Test().doSomething(request, param);",
                "String sql = \"{call \" + bar + \"}\";"};
        String src = source(body,
                "  private class Test {",
                "    public String doSomething(HttpServletRequest request, String param) {",
                "      java.util.List<String> valuesList = new java.util.ArrayList<String>();",
                "      valuesList.add(\"safe\");",
                "      valuesList.add(param);",
                "      valuesList.add(\"moresafe\");",
                "      valuesList.remove(0);",
                "      return valuesList.get(1);",
                "    }",
                "  }");
        assertTrue(ConstantArgs.isConstant(src, sink(body)));
    }

    @Test
    void lineOutsideAnyMethodIsNotDecided() {
        String[] body = {"String sql = \"SELECT 1\";"};
        assertFalse(ConstantArgs.isConstant(source(body), 1));
    }

    @Test
    void judgeSkipsLlmForConstantArgs() {
        String[] body = {"String sql = \"SELECT * FROM U WHERE N='foo'\";"};
        FakeLlm llm = new FakeLlm();
        JudgeRequest request = new JudgeRequest(new AnalysisFinding("job", "f1", "JAVA", "CWE-89", "SQL 인젝션", "HIGH",
                "FindSecBugs", "SQL_INJECTION_JDBC", "m", sink(body), "/work/job/A.java"), source(body));

        JudgeResponse response = new JudgeService(llm, "m", java.time.Duration.ofSeconds(5)).judge(request);

        assertEquals("LIKELY_FALSE_POSITIVE", response.llm().verdict());
        assertTrue(llm.prompts.isEmpty(), "상수로 판정되면 LLM을 부르지 않는다");
    }

    @Test
    void breakOutOfLoopKeepsInputPath() {
        assertFalse(constant(
                "String bar = \"safe\";",
                "for (String v : names) {",
                "    if (v.equals(\"x\")) { bar = param; break; }",
                "    bar = \"safe\";",
                "}",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void breakInsideIfInSwitchKeepsInputPath() {
        assertFalse(constant(
                "String bar;",
                "char c = 'A';",
                "switch (c) {",
                "    case 'A':",
                "        bar = param;",
                "        if (param.isEmpty()) break;",
                "        bar = \"safe\";",
                "        break;",
                "    default: bar = \"safe\";",
                "}",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void catchSeesValuesAssignedInsideTry() {
        assertFalse(constant(
                "String bar = \"safe\";",
                "try {",
                "    bar = param;",
                "    check(bar);",
                "    bar = \"safe\";",
                "} catch (Exception e) {",
                "    log(e);",
                "}",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"));
    }

    @Test
    void arrowSwitchDoesNotFallThrough() {
        String[] body = {
                "String bar;",
                "char c = 'B';",
                "switch (c) {",
                "    case 'A' -> bar = \"safe\";",
                "    case 'B' -> bar = param;",
                "    default -> bar = \"safe\";",
                "}",
                "String sql = \"SELECT * FROM U WHERE N='\" + bar + \"'\";"};
        assertFalse(constant(body));
        body[1] = "char c = 'A';";
        assertTrue(constant(body));
    }

    @Test
    void builderChangedInsideLambdaIsNotConstant() {
        assertFalse(constant(
                "StringBuilder sb = new StringBuilder(\"SELECT * FROM U WHERE N='\");",
                "names.forEach(n -> sb.append(param));",
                "String sql = sb.toString();"));
    }

    @Test
    void arrayPassedToUnknownMethodIsNotConstant() {
        assertFalse(constant(
                "String[] parts = {\"safe\"};",
                "helper.fill(parts, param);",
                "String sql = \"SELECT * FROM U WHERE N='\" + parts[0] + \"'\";"));
    }

    @Test
    void aliasedBuilderChangeIsNotConstant() {
        assertFalse(constant(
                "StringBuilder sb = new StringBuilder(\"SELECT * FROM U WHERE N='\");",
                "StringBuilder other = sb;",
                "other.append(param);",
                "String sql = sb.toString();"));
    }

    @Test
    void builderStoredInListThenChangedIsNotConstant() {
        assertFalse(constant(
                "StringBuilder sb = new StringBuilder(\"SELECT 1\");",
                "java.util.List<StringBuilder> list = new java.util.ArrayList<>();",
                "list.add(sb);",
                "sb.append(param);",
                "String sql = list.get(0).toString();"));
    }
}
