package secureview.llm;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.Range;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.FieldDeclaration;
import com.github.javaparser.ast.expr.SimpleName;

import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * S4 컨텍스트 추출: 경고 라인을 포함한 함수 전체와, 그 함수가 쓰는 클래스 필드 선언을 꺼낸다.
 * 필드 선언이 없으면 LLM이 "TABLE"이 상수인지 외부 입력인지 알 수 없기 때문이다.
 * 함수를 찾지 못했거나 너무 길면 경고 라인 ±30줄 조각으로 대신한다.
 * C 함수 범위는 {@link CFunctionFinder}로 찾는다.
 */
public final class ContextExtractor {

    static final int WINDOW = 30;
    static final int MAX_FUNCTION_LINES = 150;

    public CodeContext extract(Finding finding, String source) {
        List<String> lines = source.lines().toList();
        Optional<CallableDeclaration<?>> function = finding.file().endsWith(".java")
                ? javaCallableAt(source, finding.startLine())
                : Optional.empty();
        Optional<Range> range = function.flatMap(Node::getRange);

        if (range.isPresent() && range.get().end.line - range.get().begin.line + 1 <= MAX_FUNCTION_LINES) {
            SortedMap<Integer, String> related = new TreeMap<>();
            for (int line : fieldLinesUsedBy(function.get())) {
                related.put(line, lines.get(line - 1));
            }
            int start = range.get().begin.line;
            int end = range.get().end.line;
            return new CodeContext(finding.file(), start, end, lines.subList(start - 1, end), true, related);
        }
        if (finding.file().endsWith(".c") || finding.file().endsWith(".h")) {
            Optional<CFunctionFinder.Range> c = CFunctionFinder.functionAt(source, finding.startLine());
            if (c.isPresent() && c.get().endLine() - c.get().startLine() + 1 <= MAX_FUNCTION_LINES) {
                int start = c.get().startLine();
                int end = c.get().endLine();
                return new CodeContext(finding.file(), start, end, lines.subList(start - 1, end), true, new TreeMap<>());
            }
        }
        // 줄 번호가 파일 범위를 벗어나도 파일 안의 조각을 돌려준다.
        int size = lines.size();
        int start = Math.max(1, Math.min(size, finding.startLine() - WINDOW));
        int end = Math.max(Math.min(start, size), Math.min(size, finding.endLine() + WINDOW));
        return new CodeContext(finding.file(), start, end, lines.subList(start - 1, end), false, new TreeMap<>());
    }

    /** 경고 라인을 포함한 Java 메서드·생성자 이름. C는 아직 이름을 찾지 않는다. */
    public Optional<String> functionName(Finding finding, String source) {
        return finding.file().endsWith(".java")
                ? javaCallableAt(source, finding.startLine()).map(CallableDeclaration::getNameAsString)
                : Optional.empty();
    }

    /** line을 포함하는 메서드·생성자 중 가장 안쪽 것 (내부 클래스 메서드 대비). */
    @SuppressWarnings({"rawtypes", "unchecked"})
    private static Optional<CallableDeclaration<?>> javaCallableAt(String source, int line) {
        // JavaParser 객체는 스레드 간에 공유하면 결과가 섞이므로 호출마다 새로 만든다.
        ParseResult<CompilationUnit> result = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)).parse(source);
        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            return Optional.empty();
        }
        List<CallableDeclaration> callables = result.getResult().get().findAll(CallableDeclaration.class);
        return callables.stream()
                .<CallableDeclaration<?>>map(c -> c)
                .filter(c -> c.getRange().filter(r -> r.begin.line <= line && line <= r.end.line).isPresent())
                .min(Comparator.comparingInt(c -> c.getRange().get().end.line - c.getRange().get().begin.line));
    }

    /** 함수 안에 이름이 나오는, 바깥 클래스의 필드 선언 라인들. */
    private static Set<Integer> fieldLinesUsedBy(CallableDeclaration<?> function) {
        Set<String> used = function.findAll(SimpleName.class).stream()
                .map(SimpleName::asString)
                .collect(Collectors.toSet());
        return function.findAncestor(ClassOrInterfaceDeclaration.class).stream()
                .flatMap(type -> type.getFields().stream())
                .filter(field -> field.getVariables().stream().anyMatch(v -> used.contains(v.getNameAsString())))
                .map(FieldDeclaration::getRange)
                .flatMap(Optional::stream)
                .flatMap(r -> IntStream.rangeClosed(r.begin.line, r.end.line).boxed())
                .collect(Collectors.toSet());
    }
}
