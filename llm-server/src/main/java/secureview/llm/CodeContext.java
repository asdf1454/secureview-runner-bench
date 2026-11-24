package secureview.llm;

import java.util.List;
import java.util.SortedMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * S4 출력: 경고 라인을 포함한 코드 조각. 라인 번호는 원본 파일 기준(1부터).
 *
 * @param wholeFunction true면 함수 전체, false면 경고 라인 ±30줄 조각
 * @param related       함수가 쓰는 클래스 필드 선언 (라인 번호 → 코드). 상수 여부 판단용
 */
public record CodeContext(String file, int startLine, int endLine, List<String> lines,
                          boolean wholeFunction, SortedMap<Integer, String> related) {

    public boolean contains(int line) {
        return (line >= startLine && line <= endLine) || related.containsKey(line);
    }

    /** "42| code" 형식으로 원본 라인 번호를 붙인 코드. 필드 선언이 있으면 앞에 두고 "..."로 구분한다. */
    public String numbered() {
        String body = IntStream.range(0, lines.size())
                .mapToObj(i -> (startLine + i) + "| " + lines.get(i))
                .collect(Collectors.joining("\n"));
        if (related.isEmpty()) {
            return body;
        }
        String fields = related.entrySet().stream()
                .map(e -> e.getKey() + "| " + e.getValue())
                .collect(Collectors.joining("\n"));
        return fields + "\n...\n" + body;
    }
}
