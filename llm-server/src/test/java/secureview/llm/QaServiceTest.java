package secureview.llm;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.*;

class QaServiceTest {

    private static final Finding FINDING =
            new Finding("F-001", "UserDao.java", 16, 16, "SQL_INJECTION_JDBC", 89, "HIGH", "m", List.of("spotbugs"));
    private static final CodeContext CONTEXT = new CodeContext("UserDao.java", 14, 17,
            List.of("public ResultSet find(String name) {", "  Statement st = conn.createStatement();",
                    "  return st.executeQuery(\"...\" + name + \"'\");", "}"), true, new TreeMap<>());
    private static final Verdict VERDICT =
            new Verdict(Verdict.Result.TRUE_POSITIVE, 0.9, List.of(16), "입력을 문자열로 이어 붙임", null);

    @Test
    void promptCarriesCodeVerdictAndQuestion() {
        FakeLlm llm = new FakeLlm("{\"answer\":\"14번 줄의 매개변수 name입니다.\"}");

        Optional<String> answer = new QaService(llm).ask(FINDING, CONTEXT, VERDICT, List.of(), "이 입력은 어디서 들어오나요?");

        assertEquals("14번 줄의 매개변수 name입니다.", answer.orElseThrow());
        String prompt = llm.prompts.get(0);
        assertTrue(prompt.contains("16|   return st.executeQuery"));
        assertTrue(prompt.contains("입력을 문자열로 이어 붙임"));
        assertTrue(prompt.contains("이 입력은 어디서 들어오나요?"));
    }

    @Test
    void keepsOnlyRecentTurnsInPrompt() {
        FakeLlm llm = new FakeLlm("{\"answer\":\"a\"}");
        List<QaService.Turn> history = new java.util.ArrayList<>();
        for (int i = 1; i <= QaService.MAX_HISTORY + 1; i++) {
            history.add(new QaService.Turn("질문번호" + i + "끝", "답변" + i));
        }

        new QaService(llm).ask(FINDING, CONTEXT, VERDICT, history, "다음 질문");

        String prompt = llm.prompts.get(0);
        assertFalse(prompt.contains("질문번호1끝"), "가장 오래된 대화는 빠져야 한다");
        assertTrue(prompt.contains("질문번호" + (QaService.MAX_HISTORY + 1) + "끝"));
    }

    @Test
    void emptyWhenAnswerNeverValid() {
        FakeLlm llm = new FakeLlm("not json", "{\"answer\":\"  \"}");

        assertTrue(new QaService(llm).ask(FINDING, CONTEXT, VERDICT, List.of(), "q").isEmpty());
        assertEquals(QaService.MAX_ATTEMPTS, llm.prompts.size());
    }

    @Test
    void worksForUndeterminedVerdictWithoutExplanation() {
        FakeLlm llm = new FakeLlm("{\"answer\":\"a\"}");
        Verdict undetermined = Verdict.undetermined("판단 불가");

        assertEquals("a", new QaService(llm).ask(FINDING, CONTEXT, undetermined, List.of(), "q").orElseThrow());
    }
}
