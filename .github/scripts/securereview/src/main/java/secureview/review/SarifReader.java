package secureview.review;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SARIF 2.1.0에서 경고를 읽는다. CWE는 규칙의 relationships(CWE 분류), 규칙·결과의 tags 순서로 찾는다.
 * CWE를 찾지 못한 경고는 LLM 판정 대상(형식 A의 cwe 필수)이 아니므로 뺀다.
 */
public final class SarifReader {

    static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern CWE_TAG = Pattern.compile("(?i)(?:external/cwe/)?cwe-?(\\d{1,6})");

    private SarifReader() {
    }

    public static List<Warning> read(String sarif) {
        JsonNode root;
        try {
            root = MAPPER.readTree(sarif);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("SARIF JSON 형식이 맞지 않습니다: " + e.getOriginalMessage());
        }
        List<Warning> warnings = new ArrayList<>();
        for (JsonNode run : root.path("runs")) {
            String tool = run.path("tool").path("driver").path("name").asText("unknown");
            JsonNode rules = run.path("tool").path("driver").path("rules");
            Map<String, JsonNode> byId = new HashMap<>();
            rules.forEach(r -> byId.put(r.path("id").asText(), r));
            for (JsonNode result : run.path("results")) {
                JsonNode rule = result.has("ruleIndex") ? rules.path(result.path("ruleIndex").asInt())
                        : byId.getOrDefault(result.path("ruleId").asText(), MAPPER.missingNode());
                JsonNode location = result.path("locations").path(0).path("physicalLocation");
                int line = location.path("region").path("startLine").asInt(0);
                Optional<String> cwe = cwe(rule, result);
                if (line < 1 || cwe.isEmpty()) {
                    continue;
                }
                String ruleId = result.path("ruleId").asText(rule.path("id").asText());
                String title = rule.path("shortDescription").path("text").asText("");
                warnings.add(new Warning(uri(location.path("artifactLocation").path("uri").asText()), line,
                        cwe.get(), severity(result.path("level").asText("warning")), ruleId,
                        title.isBlank() ? ruleId : title, result.path("message").path("text").asText(""), tool));
            }
        }
        return warnings;
    }

    private static Optional<String> cwe(JsonNode rule, JsonNode result) {
        for (JsonNode rel : rule.path("relationships")) {
            JsonNode target = rel.path("target");
            if ("CWE".equalsIgnoreCase(target.path("toolComponent").path("name").asText())
                    && target.path("id").asText().matches("\\d{1,6}")) {
                return Optional.of("CWE-" + target.path("id").asText());
            }
        }
        for (JsonNode tags : List.of(rule.path("properties").path("tags"), result.path("properties").path("tags"))) {
            for (JsonNode tag : tags) {
                Matcher m = CWE_TAG.matcher(tag.asText());
                if (m.matches()) {
                    return Optional.of("CWE-" + m.group(1));
                }
            }
        }
        return Optional.empty();
    }

    private static String uri(String uri) {
        return uri.startsWith("file://") ? uri.substring("file://".length()) : uri;
    }

    private static String severity(String level) {
        return switch (level) {
            case "error" -> "HIGH";
            case "warning" -> "MEDIUM";
            default -> "LOW";
        };
    }
}
