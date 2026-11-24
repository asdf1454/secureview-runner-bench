package secureview.llm;

/**
 * POST /internal/fix 요청 (명세에는 아직 없는 12월 범위 API, 로컬 구현).
 *
 * @param reason          판정 때 받은 설명. 없어도 된다
 * @param previousFailure 이전 수정안의 재검증 실패 이유(COMPILE_ERROR, STILL_VULNERABLE 등). 첫 시도면 null
 */
public record FixRequest(AnalysisFinding finding, String sourceCode, String reason, String previousFailure) {
}
