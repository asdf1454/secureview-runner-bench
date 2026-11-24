package secureview.llm;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** resources/prompts/{name}.txt 템플릿의 {{key}}를 값으로 바꾼다. */
final class Prompts {

    private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{(\\w+)}}");

    /** 대상 CWE 10종. 번호만 주면 LLM이 이름을 지어낸다(CWE-89를 XSS라고 하는 등). */
    private static final Map<Integer, String> CWE_NAMES = Map.of(
            89, "SQL 인젝션", 79, "크로스사이트 스크립팅(XSS)", 78, "OS 명령어 삽입", 22, "경로 조작",
            798, "하드코딩된 비밀번호·키", 120, "버퍼 오버플로", 416, "해제 후 사용", 476, "널 포인터 역참조",
            134, "포맷 스트링", 190, "정수 오버플로");

    private Prompts() {
    }

    /** 예: "CWE-89 (SQL 인젝션)" */
    static String cwe(int number) {
        String name = CWE_NAMES.get(number);
        return name == null ? "CWE-" + number : "CWE-" + number + " (" + name + ")";
    }

    static String render(String name, Map<String, String> values) {
        // 한 번에 치환하므로 값(코드) 안에 {{...}}가 있어도 다시 치환되지 않는다.
        return PLACEHOLDER.matcher(load(name)).replaceAll(m -> {
            String value = values.get(m.group(1));
            if (value == null) {
                throw new IllegalArgumentException("프롬프트 " + name + "에 값이 없는 자리: " + m.group());
            }
            return Matcher.quoteReplacement(value);
        });
    }

    /** 코드를 데이터로만 다루라는 시스템 프롬프트. */
    static String system() {
        return load("system");
    }

    /** resources/prompts/{name}.schema.json. 필드 순서는 파일에 적힌 순서를 유지한다. */
    static JsonNode schema(String name) {
        try {
            return StructuredLlm.MAPPER.readTree(read(name + ".schema.json"));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("스키마 파일 오류: " + name, e);
        }
    }

    private static String load(String name) {
        return read(name + ".txt");
    }

    private static String read(String file) {
        try (InputStream in = Prompts.class.getResourceAsStream("/prompts/" + file)) {
            if (in == null) {
                throw new IllegalArgumentException("프롬프트 파일 없음: " + file);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
