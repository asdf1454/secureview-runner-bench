package secureview.llm;

/** 경고 줄이 헝크 범위 밖이다. 서버는 400 INVALID_LINE으로 돌려준다. */
public final class InvalidLineException extends IllegalArgumentException {

    public InvalidLineException(String message) {
        super(message);
    }
}
