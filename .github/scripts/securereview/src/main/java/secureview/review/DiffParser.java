package secureview.review;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PR의 Unified Diff를 헝크로 나눈다 (설계안 Phase 1).
 * 남기는 것: .java 파일에서 실행 코드가 추가된 헝크. 빼는 것: 삭제된 파일, 이진 파일, 삭제 전용·주석 전용 헝크,
 * patch가 maxPatchBytes를 넘는 헝크, 같은 ID의 중복.
 * ID는 sha256(filePath + "\n" + header + "\n" + patch)다.
 */
public final class DiffParser {

    private static final Pattern HEADER = Pattern.compile("^@@ -(\\d+)(?:,(\\d+))? \\+(\\d+)(?:,(\\d+))? @@.*");

    private DiffParser() {
    }

    public static List<Hunk> parse(String diff, int maxPatchBytes) {
        Map<String, Hunk> hunks = new LinkedHashMap<>();
        String path = null;
        Builder current = null;
        for (String line : diff.replace("\r\n", "\n").split("\n", -1)) {
            if (line.startsWith("diff --git ")) {
                add(hunks, current, maxPatchBytes);
                current = null;
                path = null;
            } else if (current == null && line.startsWith("+++ ")) {
                String target = line.substring(4);
                path = target.startsWith("b/") ? target.substring(2) : null; // "/dev/null"은 삭제된 파일
            } else if (line.startsWith("@@")) {
                add(hunks, current, maxPatchBytes);
                Matcher m = HEADER.matcher(line);
                current = path != null && path.endsWith(".java") && m.matches() ? new Builder(path, line, m) : null;
            } else if (current != null) {
                current.accept(line);
            }
        }
        add(hunks, current, maxPatchBytes);
        return List.copyOf(hunks.values());
    }

    private static void add(Map<String, Hunk> hunks, Builder builder, int maxPatchBytes) {
        if (builder == null) {
            return;
        }
        Hunk hunk = builder.build();
        boolean code = hunk.addedLines().stream().anyMatch(a -> !isComment(a.code()));
        if (code && hunk.patch().getBytes(StandardCharsets.UTF_8).length <= maxPatchBytes) {
            hunks.putIfAbsent(hunk.id(), hunk);
        }
    }

    /** 빈 줄과 주석으로 보이는 줄. 줄 단위로만 보므로 여러 줄 주석의 가운데 줄은 "*"로 시작할 때만 안다. */
    private static boolean isComment(String code) {
        String t = code.strip();
        return t.isEmpty() || t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");
    }

    private static final class Builder {
        private final String path;
        private final String header;
        private final int oldStart;
        private final int oldCount;
        private final int newStart;
        private final int newCount;
        private final List<String> body = new ArrayList<>();
        private final List<Hunk.AddedLine> added = new ArrayList<>();
        private int newLine;

        Builder(String path, String header, Matcher m) {
            this.path = path;
            this.header = header;
            this.oldStart = Integer.parseInt(m.group(1));
            this.oldCount = m.group(2) == null ? 1 : Integer.parseInt(m.group(2));
            this.newStart = Integer.parseInt(m.group(3));
            this.newCount = m.group(4) == null ? 1 : Integer.parseInt(m.group(4));
            this.newLine = newStart;
        }

        void accept(String line) {
            if (line.isEmpty()) {
                // 줄 끝 공백을 지운 diff에서는 빈 문맥 줄이 " " 대신 ""로 온다. 헝크가 끝난 뒤의 ""는 파일 끝이다.
                if (newLine < newStart + newCount) {
                    body.add(" ");
                    newLine++;
                }
                return;
            }
            body.add(line);
            switch (line.charAt(0)) {
                case '+' -> added.add(new Hunk.AddedLine(newLine++, line.substring(1)));
                case ' ' -> newLine++;
                default -> { } // '-'와 "\ No newline at end of file"
            }
        }

        Hunk build() {
            String patch = header + "\n" + String.join("\n", body);
            return new Hunk(sha256(path + "\n" + header + "\n" + patch), path, header, oldStart, oldCount,
                    newStart, newCount, patch, List.copyOf(added));
        }
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
