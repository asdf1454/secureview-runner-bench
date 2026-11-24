package secureview.llm;

import java.util.List;

/**
 * S5 출력: LLM 판정 (계획서의 'LLM 판정' 항목).
 * confidence는 LLM이 스스로 낸 값이라 실제 정확도와 맞지 않을 수 있다. 화면에 그대로 보여 주지 않는다.
 */
public record Verdict(Result result, double confidence, List<Integer> evidenceLines,
                      String reason, Explanation explanation) {

    public enum Result { TRUE_POSITIVE, LIKELY_FALSE_POSITIVE, UNDETERMINED }

    public record Explanation(String summary, String risk, String attackExample) {
    }

    static Verdict undetermined(String reason) {
        return new Verdict(Result.UNDETERMINED, 0, List.of(), reason, null);
    }
}
