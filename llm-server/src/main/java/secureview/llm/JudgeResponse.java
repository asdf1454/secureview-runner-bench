package secureview.llm;

import java.util.List;

/** API 명세 형식 B: LLM 모듈이 웹 서버로 돌려주는 판정 하나. function은 S4, llm은 S5 결과. */
public record JudgeResponse(String findingId, Function function, Llm llm) {

    public record Function(String name, int startLine, int endLine, String code) {
    }

    public record Llm(String verdict, List<Integer> evidenceLines, String explanation, String attackExample,
                      String model, double latencySec) {
    }
}
