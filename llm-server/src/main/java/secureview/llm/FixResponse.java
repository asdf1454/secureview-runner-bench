package secureview.llm;

/**
 * POST /internal/fix 응답. function과 fixedCode는 재검증(형식 C 입력)에 그대로 넣을 수 있다.
 *
 * @param fixedCode 함수 전체를 대신할 코드. 만들지 못했으면 null이고 reason에 이유가 들어간다
 */
public record FixResponse(String findingId, Function function, String fixedCode, String reason, String model,
                          double latencySec) {

    public record Function(String name, int startLine, int endLine) {
    }
}
