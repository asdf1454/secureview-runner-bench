package secureview.llm;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * S6 수정안을 S7(재컴파일)에 넘기기 전에 값싸게 걸러 낸다. 통과해도 컴파일이나 안전을 보장하지 않는다.
 * 원본 함수 범위를 그대로 교체하므로, 수정안은 같은 선언을 가진 함수 하나여야 한다.
 */
final class FixValidator {

    private static final Pattern LINE_NUMBER = Pattern.compile("(?m)^\\s*\\d+\\|");

    private FixValidator() {
    }

    /** @return 문제가 없으면 null, 있으면 LLM에게 돌려줄 설명. */
    static String problemOf(CodeContext context, String code) {
        if (code == null || code.isBlank()) {
            return "code가 비어 있음";
        }
        if (LINE_NUMBER.matcher(code).find()) {
            return "code에 라인 번호가 들어 있음";
        }
        if (!context.wholeFunction()) {
            return null;
        }
        String original = String.join("\n", context.lines());
        return context.file().endsWith(".java") ? javaProblem(original, code) : cProblem(original, code);
    }

    private static String javaProblem(String original, String code) {
        Optional<CompilationUnit> fixed = parseAsClassBody(code);
        if (fixed.isEmpty()) {
            return "code가 Java 문법에 맞지 않음";
        }
        List<BodyDeclaration<?>> members = fixed.get().getType(0).getMembers();
        if (members.size() != 1 || !(members.get(0) instanceof CallableDeclaration<?>)) {
            return "code는 필드 선언이나 다른 멤버 없이 함수 하나만 담아야 함";
        }
        Optional<String> before = parseAsClassBody(original)
                .map(u -> u.getType(0).getMembers())
                .filter(m -> m.size() == 1)
                .map(m -> declaration(m.get(0)));
        String after = declaration(members.get(0));
        if (before.isPresent() && !before.get().equals(after)) {
            return "함수 선언이 바뀜. 원래 선언: " + before.get();
        }
        return null;
    }

    private static String declaration(BodyDeclaration<?> member) {
        String type = member instanceof MethodDeclaration m ? m.getType().asString() + " " : "";
        CallableDeclaration<?> callable = (CallableDeclaration<?>) member;
        String thrown = callable.getThrownExceptions().stream()
                .map(Object::toString)
                .sorted()
                .collect(Collectors.joining(", "));
        return type + callable.getSignature().asString() + (thrown.isEmpty() ? "" : " throws " + thrown);
    }

    private static Optional<CompilationUnit> parseAsClassBody(String members) {
        JavaParser parser = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17));
        ParseResult<CompilationUnit> result = parser.parse("class X_ {\n" + members + "\n}");
        return result.isSuccessful() ? result.getResult() : Optional.empty();
    }

    private static String cProblem(String original, String code) {
        String stripped = code.strip();
        List<CFunctionFinder.Range> functions = CFunctionFinder.functions(stripped);
        if (functions.size() != 1 || functions.get(0).startLine() != 1
                || functions.get(0).endLine() != stripped.lines().count()) {
            return "code는 중괄호 짝이 맞는 함수 하나만 담아야 함";
        }
        String before = cFunctionName(original);
        if (!before.isEmpty() && !before.equals(cFunctionName(stripped))) {
            return "함수 이름이 바뀜. 원래 이름: " + before;
        }
        return null;
    }

    /** 첫 여는 괄호 바로 앞의 식별자. */
    private static String cFunctionName(String source) {
        int paren = source.indexOf('(');
        if (paren < 0) {
            return "";
        }
        int end = paren;
        while (end > 0 && Character.isWhitespace(source.charAt(end - 1))) {
            end--;
        }
        int start = end;
        while (start > 0 && (Character.isLetterOrDigit(source.charAt(start - 1)) || source.charAt(start - 1) == '_')) {
            start--;
        }
        return source.substring(start, end);
    }
}
