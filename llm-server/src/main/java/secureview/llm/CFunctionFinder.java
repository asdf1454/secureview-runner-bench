package secureview.llm;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * C 소스에서 어떤 줄을 포함한 함수의 범위를 찾는다. 주석·문자열·전처리 줄을 건너뛰며 최상위 중괄호를 추적한다.
 * 전처리 분기로 중괄호 짝이 맞지 않으면 함수를 믿을 수 없으므로 찾지 않은 것으로 처리한다. (호출자는 ±30줄 조각을 쓴다)
 */
final class CFunctionFinder {

    record Range(int startLine, int endLine) {
    }

    private CFunctionFinder() {
    }

    static Optional<Range> functionAt(String source, int line) {
        return functions(source).stream()
                .filter(f -> f.startLine() <= line && line <= f.endLine())
                .findFirst();
    }

    /** 최상위 함수 범위 목록. 중괄호 짝이 맞지 않으면 빈 목록. */
    static List<Range> functions(String source) {
        List<Range> found = new ArrayList<>();
        int depth = 0;
        int current = 1;
        int headerStart = -1;
        boolean hasParen = false;
        boolean hasEquals = false;
        boolean function = false;
        boolean lineHasCode = false;

        for (int i = 0; i < source.length(); i++) {
            char c = source.charAt(i);
            char next = i + 1 < source.length() ? source.charAt(i + 1) : '\0';
            if (c == '\n') {
                current++;
                lineHasCode = false;
            } else if (c == '/' && next == '/') {
                i = endOfLine(source, i) - 1;
            } else if (c == '/' && next == '*') {
                int end = source.indexOf("*/", i + 2);
                end = end < 0 ? source.length() - 1 : end + 1;
                current += newlines(source, i, end);
                i = end;
            } else if (c == '#' && !lineHasCode) {
                int end = endOfDirective(source, i);
                current += newlines(source, i, end);
                i = end - 1;
            } else if (c == '"' || c == '\'') {
                lineHasCode = true;
                if (depth == 0 && headerStart < 0) {
                    headerStart = current;
                }
                i = endOfLiteral(source, i, c);
            } else if (!Character.isWhitespace(c)) {
                lineHasCode = true;
                if (depth == 0 && headerStart < 0 && c != ';' && c != '}') {
                    headerStart = current;
                }
                if (c == '{') {
                    if (depth == 0) {
                        function = hasParen && !hasEquals;
                    }
                    depth++;
                } else if (c == '}') {
                    if (--depth < 0) {
                        return List.of();
                    }
                    if (depth == 0) {
                        if (function) {
                            found.add(new Range(headerStart, current));
                        }
                        headerStart = -1;
                        hasParen = false;
                        hasEquals = false;
                    }
                } else if (depth == 0 && c == ';') {
                    headerStart = -1;
                    hasParen = false;
                    hasEquals = false;
                } else if (depth == 0 && c == '(') {
                    hasParen = true;
                } else if (depth == 0 && c == '=') {
                    hasEquals = true;
                }
            }
        }
        return depth == 0 ? found : List.of();
    }

    private static int endOfLine(String s, int from) {
        int end = s.indexOf('\n', from);
        return end < 0 ? s.length() : end;
    }

    /** 전처리 줄의 끝(줄바꿈 위치). 줄 끝의 \ 는 다음 줄로 이어진다. */
    private static int endOfDirective(String s, int from) {
        int end = endOfLine(s, from);
        while (end < s.length() && end > 0
                && (s.charAt(end - 1) == '\\' || (s.charAt(end - 1) == '\r' && end > 1 && s.charAt(end - 2) == '\\'))) {
            end = endOfLine(s, end + 1);
        }
        return end;
    }

    private static int endOfLiteral(String s, int from, char quote) {
        for (int i = from + 1; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == quote || c == '\n') {
                return c == '\n' ? i - 1 : i;
            }
        }
        return s.length() - 1;
    }

    private static int newlines(String s, int from, int to) {
        int count = 0;
        for (int i = from; i < to && i < s.length(); i++) {
            if (s.charAt(i) == '\n') {
                count++;
            }
        }
        return count;
    }
}
