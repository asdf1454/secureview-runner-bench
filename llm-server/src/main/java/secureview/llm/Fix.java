package secureview.llm;

import java.util.List;

/**
 * S6 출력: 수정안 (설명서의 '수정안' 항목). functionRange의 [시작, 끝] 줄 범위를 code로 통째로 교체한다.
 *
 * @param verification S7(재검증, 채무진 님 담당)이 채운다. S6 직후에는 null.
 */
public record Fix(List<Integer> functionRange, String code, String reason, Verification verification) {

    public record Verification(boolean compiled, boolean warningResolved, int newHighWarnings,
                               Status status) {
        public enum Status { VERIFIED, FAILED }
    }
}
