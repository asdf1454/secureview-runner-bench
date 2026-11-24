package secureview.llm;

/** API 명세 POST /internal/judge 요청: 형식 A 경고 하나와 파일 전체 내용. */
public record JudgeRequest(AnalysisFinding finding, String sourceCode) {
}
