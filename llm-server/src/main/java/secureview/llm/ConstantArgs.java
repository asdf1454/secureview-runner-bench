package secureview.llm;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ParserConfiguration;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.CallableDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.*;
import com.github.javaparser.ast.stmt.*;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * SQL 호출에 들어가는 문자열이 함수 안에서 상수로만 만들어지는지 코드로 판정한다.
 * 7B LLM은 상수 조건 분기, List·Map에서 꺼낸 값, 상수 switch를 자주 잘못 읽고, 계산 결과를 알려 줘도 무시했다
 * (OWASP Benchmark SQL 표본). 그래서 계산할 수 있는 경우는 LLM에 묻지 않고 여기서 오탐으로 판정한다.
 *
 * 확실할 때만 true다. 매개변수, 필드, 모르는 메서드의 결과, 모르는 메서드에 넘겨진 List·StringBuilder는 모두 "상수 아님"으로 본다.
 * 값이 정확히 계산되는 조건과 switch만 한쪽 갈래를 버리고, 나머지 갈래·반복문·catch는 모든 경우를 합친다.
 */
final class ConstantArgs {

    /**
     * CWE별 위험한 호출. methods는 메서드 이름, constructors는 new 뒤의 타입 이름.
     * firstArgOnly면 첫 인자만 본다 (SQL은 둘째 인자부터 RowMapper 같은 것이라 상수가 아니어도 된다). 아니면 모든 인자를 본다.
     */
    record Sink(Set<String> methods, Set<String> constructors, boolean firstArgOnly) {
    }

    static final Map<Integer, Sink> SINKS = Map.of(
            89, new Sink(Set.of("executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "addBatch",
                    "prepareStatement", "prepareCall", "query", "queryForObject", "queryForList", "queryForMap", "queryForRowSet",
                    "queryForLong", "queryForInt", "update", "batchUpdate", "createQuery", "createSQLQuery", "createNativeQuery"),
                    Set.of(), true),
            78, new Sink(Set.of("exec", "command"), Set.of("ProcessBuilder"), false),
            22, new Sink(Set.of("get", "of"), Set.of("File", "FileInputStream", "FileOutputStream", "FileReader", "FileWriter",
                    "RandomAccessFile"), false),
            79, new Sink(Set.of("print", "println", "write", "format", "printf", "append"), Set.of(), false));

    /** 상수 문자열에 써도 결과가 상수인 String 메서드. */
    private static final Set<String> PURE = Set.of("toString", "trim", "strip", "substring", "toLowerCase", "toUpperCase",
            "intern", "replace", "replaceAll", "replaceFirst", "concat", "charAt", "valueOf", "format", "join", "split",
            "length", "toCharArray", "getBytes");

    private ConstantArgs() {
    }

    static boolean isConstant(String source, int line) {
        return isConstant(source, line, 89);
    }

    /**
     * source의 line에 있는 위험한 호출의 인자가 모두 공격자가 바꿀 수 없는 값으로만 만들어지면 true. 같은 파일의 메서드 호출은 따라간다.
     * 상수가 아니어도 공격자가 바꿀 수 없다고 보는 값은 두 가지다: System.getProperty("...")와 대문자 이름의 필드(Utils.TESTFILES_DIR 같은 상수 관례).
     */
    static boolean isConstant(String source, int line, int cwe) {
        Sink spec = SINKS.get(cwe);
        if (spec == null) {
            return false;
        }
        ParseResult<CompilationUnit> parsed = new JavaParser(
                new ParserConfiguration().setLanguageLevel(ParserConfiguration.LanguageLevel.JAVA_17)).parse(source);
        if (!parsed.isSuccessful() || parsed.getResult().isEmpty()) {
            return false;
        }
        CompilationUnit unit = parsed.getResult().get();
        @SuppressWarnings("rawtypes")
        Optional<CallableDeclaration> function = unit.findAll(CallableDeclaration.class).stream()
                .filter(c -> covers(c, line))
                .min(Comparator.comparingInt(c -> c.getRange().get().end.line - c.getRange().get().begin.line));
        if (function.isEmpty()) {
            return false;
        }
        List<Expression> sinks = function.get().findAll(Expression.class).stream()
                .filter(e -> covers(e, line) && isSink(e, spec))
                .toList();
        if (sinks.isEmpty()) {
            return false;
        }
        Interpreter interpreter = new Interpreter(sinks, unit, spec);
        function.get().findFirst(BlockStmt.class).ifPresent(b -> interpreter.exec((BlockStmt) b, new State()));
        return interpreter.allSinksConstant();
    }

    private static boolean isSink(Expression e, Sink spec) {
        if (e instanceof MethodCallExpr m && !m.getArguments().isEmpty() && spec.methods().contains(m.getNameAsString())) {
            // 경로 조작의 get·of는 Paths.get, Path.of만
            return !(spec.constructors().contains("File") && m.getScope().map(Object::toString).filter(s -> s.endsWith("Paths")
                    || s.endsWith("Path")).isEmpty());
        }
        return e instanceof ObjectCreationExpr o && !o.getArguments().isEmpty()
                && spec.constructors().contains(o.getType().getNameAsString());
    }

    private static boolean covers(Node node, int line) {
        return node.getRange().map(r -> r.begin.line <= line && line <= r.end.line).orElse(false);
    }

    // ---- 값 ----

    /** 문자열·숫자 값. constant면 외부 입력이 섞이지 않았고, exact가 null이 아니면 정확한 값까지 안다. */
    record Scalar(boolean constant, Object exact) implements Value {
        static final Scalar UNKNOWN = new Scalar(false, null);
        static final Scalar SAFE = new Scalar(true, null);

        static Scalar of(Object exact) {
            return new Scalar(true, exact);
        }
    }

    /** 지역 List. exact면 원소 순서를 정확히 안다. 아니면 모든 원소가 상수인지만 안다. */
    record ListValue(List<Scalar> items, boolean exact) implements Value {
    }

    /** 지역 Map. exact면 키별 값을 정확히 안다. */
    record MapValue(Map<String, Scalar> entries, boolean exact) implements Value {
    }

    sealed interface Value permits Scalar, ListValue, MapValue {
        default Scalar asScalar() {
            if (this instanceof Scalar s) {
                return s;
            }
            return Scalar.UNKNOWN; // 컬렉션 자체를 문자열로 쓰면 따지지 않는다
        }

        default boolean allConstant() {
            if (this instanceof ListValue l) {
                return l.items().stream().allMatch(Scalar::constant);
            }
            if (this instanceof MapValue m) {
                return m.entries().values().stream().allMatch(Scalar::constant);
            }
            return ((Scalar) this).constant();
        }
    }

    static Value merge(Value a, Value b) {
        if (a == null || b == null) {
            return a == null ? (b == null ? null : weaken(b)) : weaken(a);
        }
        if (a.equals(b)) {
            return a;
        }
        if (a instanceof Scalar x && b instanceof Scalar y) {
            return new Scalar(x.constant() && y.constant(), Objects.equals(x.exact(), y.exact()) ? x.exact() : null);
        }
        boolean constant = a.allConstant() && b.allConstant();
        if (a instanceof ListValue && b instanceof ListValue) {
            return new ListValue(List.of(constant ? Scalar.SAFE : Scalar.UNKNOWN), false);
        }
        if (a instanceof MapValue && b instanceof MapValue) {
            return new MapValue(Map.of("", constant ? Scalar.SAFE : Scalar.UNKNOWN), false);
        }
        return Scalar.UNKNOWN;
    }

    /** 한쪽 갈래에만 있는 변수: 다른 갈래에서는 선언 전이므로 정확한 값은 버린다. */
    private static Value weaken(Value v) {
        return v instanceof Scalar s ? new Scalar(s.constant(), null) : v;
    }

    /** 변수 이름 → 값. 없는 이름(매개변수, 필드)은 상수가 아니다. */
    static final class State {
        final Map<String, Value> vars = new HashMap<>();

        State copy() {
            State s = new State();
            s.vars.putAll(vars);
            return s;
        }

        Value get(String name) {
            return vars.getOrDefault(name, Scalar.UNKNOWN);
        }

        static State merge(State a, State b) {
            State s = new State();
            Set<String> names = new java.util.HashSet<>(a.vars.keySet());
            names.addAll(b.vars.keySet());
            for (String n : names) {
                Value v = ConstantArgs.merge(a.vars.get(n), b.vars.get(n));
                if (v != null) {
                    s.vars.put(n, v);
                }
            }
            return s;
        }
    }

    // ---- 실행 ----

    private static final class Interpreter {
        private final Map<Expression, Boolean> sinks = new LinkedHashMap<>();
        private final Sink spec;
        /** StringBuilder·StringBuffer 변수. 문자열과 달리 다른 메서드에 넘기면 바뀔 수 있다. */
        private final Set<String> builders = new java.util.HashSet<>();

        /** 같은 파일에 선언된 메서드와 클래스 이름. 호출을 따라갈 때 쓴다. */
        private final List<MethodDeclaration> methods;
        private final Set<String> classes = new java.util.HashSet<>();
        /** 따라가는 중인 메서드마다 return 값을 모은다. 깊이 제한과 재귀 방지에도 쓴다. */
        private final java.util.Deque<List<Value>> returns = new java.util.ArrayDeque<>();
        private final java.util.Deque<MethodDeclaration> calling = new java.util.ArrayDeque<>();
        /** 안쪽 반복문·switch부터, break·continue 시점의 상태 */
        private final java.util.Deque<List<State>> breaks = new java.util.ArrayDeque<>();
        private final java.util.Deque<List<State>> continues = new java.util.ArrayDeque<>();

        Interpreter(List<Expression> sinks, CompilationUnit unit, Sink spec) {
            this.spec = spec;
            sinks.forEach(s -> this.sinks.put(s, null));
            methods = unit.findAll(MethodDeclaration.class);
            unit.findAll(ClassOrInterfaceDeclaration.class).forEach(c -> classes.add(c.getNameAsString()));
        }

        /** 같은 파일의 메서드 하나로 정해지는 호출이면 그 메서드. f(), this.f(), new 내부클래스().f() 만 따라간다. */
        private Optional<MethodDeclaration> target(MethodCallExpr m) {
            boolean local = m.getScope().isEmpty() || m.getScope().get().isThisExpr()
                    || m.getScope().get() instanceof ObjectCreationExpr o && o.getArguments().isEmpty()
                    && classes.contains(o.getType().getNameAsString());
            if (!local || returns.size() >= 3) {
                return Optional.empty();
            }
            List<MethodDeclaration> found = methods.stream()
                    .filter(d -> d.getNameAsString().equals(m.getNameAsString()) && d.getParameters().size() == m.getArguments().size()
                            && d.getBody().isPresent() && !calling.contains(d))
                    .toList();
            return found.size() == 1 ? Optional.of(found.get(0)) : Optional.empty();
        }

        /** 매개변수에 인자 값을 넣고 본문을 실행해, 모든 return 값을 합친 것을 돌려준다. */
        private Value inline(MethodDeclaration d, List<Value> args) {
            State st = new State();
            for (int i = 0; i < args.size(); i++) {
                st.vars.put(d.getParameter(i).getNameAsString(), args.get(i));
            }
            returns.push(new ArrayList<>());
            calling.push(d);
            try {
                exec(d.getBody().get(), st);
            } finally {
                calling.pop();
            }
            List<Value> values = returns.pop();
            return values.stream().reduce(ConstantArgs::merge).orElse(Scalar.UNKNOWN);
        }

        boolean allSinksConstant() {
            return sinks.values().stream().allMatch(Boolean.TRUE::equals);
        }

        /** 문장을 실행한 뒤의 상태. st를 직접 바꿀 수 있으니 갈래마다 copy를 넘긴다. */
        State exec(Statement s, State st) {
            if (s instanceof BlockStmt b) {
                State cur = st;
                for (Statement child : b.getStatements()) {
                    cur = exec(child, cur);
                }
                return cur;
            }
            if (s instanceof ExpressionStmt e) {
                eval(e.getExpression(), st);
                return st;
            }
            if (s instanceof IfStmt i) {
                Scalar cond = eval(i.getCondition(), st).asScalar();
                if (cond.exact() instanceof Boolean taken) {
                    return taken ? exec(i.getThenStmt(), st) : i.getElseStmt().map(e -> exec(e, st)).orElse(st);
                }
                State then = exec(i.getThenStmt(), st.copy());
                State other = i.getElseStmt().map(e -> exec(e, st.copy())).orElse(st);
                return State.merge(then, other);
            }
            if (s instanceof SwitchStmt sw) {
                return execSwitch(sw, st);
            }
            if (s instanceof TryStmt t) {
                t.getResources().forEach(r -> eval(r, st));
                State after = exec(t.getTryBlock(), st.copy());
                // 예외는 try 중간 어디서든 날 수 있다. try 안에서 바뀌는 변수는 catch에서 어떤 값이든 될 수 있다고 본다
                State caught = State.merge(st, after);
                t.getTryBlock().findAll(AssignExpr.class).forEach(a -> caught.vars.put(a.getTarget().toString(), Scalar.UNKNOWN));
                t.getTryBlock().findAll(MethodCallExpr.class).forEach(c -> c.getScope()
                        .filter(Expression::isNameExpr).ifPresent(n -> {
                            String name = n.asNameExpr().getNameAsString();
                            if (caught.vars.containsKey(name) && (builders.contains(name) || !(caught.get(name) instanceof Scalar))) {
                                caught.vars.put(name, Scalar.UNKNOWN);
                            }
                        }));
                State result = after;
                for (CatchClause c : t.getCatchClauses()) {
                    result = State.merge(result, exec(c.getBody(), caught.copy()));
                }
                return t.getFinallyBlock().isPresent() ? exec(t.getFinallyBlock().get(), result) : result;
            }
            if (s instanceof ForEachStmt f) {
                Value iterable = eval(f.getIterable(), st);
                State loop = st.copy();
                loop.vars.put(f.getVariable().getVariables().get(0).getNameAsString(), new Scalar(iterable.allConstant(), null));
                return loopMerge(f.getBody(), st, loop);
            }
            if (s instanceof ForStmt f) {
                f.getInitialization().forEach(e -> eval(e, st));
                State loop = st.copy();
                f.getCompare().ifPresent(e -> eval(e, loop));
                f.getUpdate().forEach(e -> eval(e, loop));
                return loopMerge(f.getBody(), st, loop);
            }
            if (s instanceof WhileStmt w) {
                eval(w.getCondition(), st);
                return loopMerge(w.getBody(), st, st.copy());
            }
            if (s instanceof DoStmt d) {
                return loopMerge(d.getBody(), st, st.copy());
            }
            if (s instanceof ReturnStmt r) {
                Value v = r.getExpression().map(e -> eval(e, st)).orElse(Scalar.SAFE);
                if (!returns.isEmpty()) {
                    returns.peek().add(v);
                }
                return st;
            }
            if (s instanceof BreakStmt b) {
                jump(b.getLabel().isPresent(), breaks, st);
                return st;
            }
            if (s instanceof ContinueStmt c) {
                jump(c.getLabel().isPresent(), continues, st);
                return st;
            }
            if (s instanceof ThrowStmt || s instanceof EmptyStmt) {
                return st;
            }
            if (s instanceof LabeledStmt l) {
                return exec(l.getStatement(), st);
            }
            // 모르는 문장: 안에서 대입되는 변수는 모두 상수가 아니게 하고, 안의 SQL 호출은 판정하지 않는다
            s.findAll(AssignExpr.class).forEach(a -> st.vars.put(a.getTarget().toString(), Scalar.UNKNOWN));
            s.findAll(Expression.class).forEach(c -> sinks.replace(c, false));
            return st;
        }

        /**
         * break·continue 시점의 상태를 모은다. 그 뒤 문장은 같은 갈래에서 실행되지 않지만 여기서는 계속 실행하므로,
         * 빠져나간 시점의 값을 따로 모아 반복문·switch가 끝날 때 합친다. 이름 붙은 break·continue는 따라가지 않고 판정을 포기한다.
         */
        private void jump(boolean labeled, java.util.Deque<List<State>> targets, State st) {
            if (labeled || targets.isEmpty()) {
                sinks.replaceAll((call, constant) -> false);
            } else {
                targets.peek().add(st.copy());
            }
        }

        /** 반복문 본문은 0번 또는 여러 번 돈다. 두 번 돌려 바뀐 값을 퍼뜨리고, 처음 상태·break 시점 상태와 합친다. */
        private State loopMerge(Statement body, State before, State loop) {
            breaks.push(new ArrayList<>());
            continues.push(new ArrayList<>());
            State once = exec(body, loop);
            for (State c : continues.peek()) {
                once = State.merge(once, c);
            }
            State twice = exec(body, State.merge(loop, once));
            for (State c : continues.pop()) {
                twice = State.merge(twice, c);
            }
            State result = State.merge(before, State.merge(once, twice));
            for (State b : breaks.pop()) {
                result = State.merge(result, b);
            }
            return result;
        }

        private State execSwitch(SwitchStmt sw, State st) {
            breaks.push(new ArrayList<>());
            State result = execSwitchBody(sw, st);
            for (State b : breaks.pop()) {
                result = State.merge(result, b);
            }
            return result;
        }

        private State execSwitchBody(SwitchStmt sw, State st) {
            Scalar selector = eval(sw.getSelector(), st).asScalar();
            List<SwitchEntry> entries = sw.getEntries();
            if (selector.exact() != null) {
                int start = -1;
                for (int i = 0; i < entries.size() && start < 0; i++) {
                    for (Expression label : entries.get(i).getLabels()) {
                        if (selector.exact().equals(eval(label, st).asScalar().exact())) {
                            start = i;
                        }
                    }
                }
                for (int i = 0; i < entries.size() && start < 0; i++) {
                    if (entries.get(i).getLabels().isEmpty()) {
                        start = i; // default
                    }
                }
                return start < 0 ? st : runFrom(entries, start, st);
            }
            State result = st; // 어느 case에도 안 맞는 경우
            for (int i = 0; i < entries.size(); i++) {
                result = State.merge(result, runFrom(entries, i, st.copy()));
            }
            return result;
        }

        /** start번째 case부터 바로 아래의 break를 만날 때까지 실행한다 (fall-through 포함). 화살표 case(->)는 그 case만. */
        private State runFrom(List<SwitchEntry> entries, int start, State st) {
            for (int i = start; i < entries.size(); i++) {
                for (Statement s : entries.get(i).getStatements()) {
                    if (s instanceof BreakStmt b && b.getLabel().isEmpty()) {
                        return st;
                    }
                    st = exec(s, st);
                }
                if (entries.get(i).getType() != SwitchEntry.Type.STATEMENT_GROUP) {
                    return st;
                }
            }
            return st;
        }

        Value eval(Expression e, State st) {
            if (sinks.containsKey(e)) {
                // 호출의 부작용이 반영되기 전에 인자를 본다
                List<Expression> args = e instanceof MethodCallExpr m ? m.getArguments() : ((ObjectCreationExpr) e).getArguments();
                State copy = st.copy();
                boolean constant = (spec.firstArgOnly() ? args.subList(0, 1) : args).stream()
                        .map(a -> eval(a, copy)).allMatch(Value::allConstant);
                sinks.put(e, constant && !Boolean.FALSE.equals(sinks.get(e)));
            }
            return evalInner(e, st);
        }

        private Value evalInner(Expression e, State st) {
            if (e instanceof EnclosedExpr en) {
                return eval(en.getInner(), st);
            }
            if (e instanceof CastExpr c) {
                return eval(c.getExpression(), st);
            }
            if (e instanceof StringLiteralExpr s) {
                return Scalar.of(s.asString());
            }
            if (e instanceof TextBlockLiteralExpr t) {
                return Scalar.of(t.asString());
            }
            if (e instanceof IntegerLiteralExpr i) {
                return Scalar.of(i.asNumber().longValue());
            }
            if (e instanceof LongLiteralExpr l) {
                return Scalar.of(l.asNumber().longValue());
            }
            if (e instanceof CharLiteralExpr c) {
                return Scalar.of(c.asChar());
            }
            if (e instanceof BooleanLiteralExpr b) {
                return Scalar.of(b.getValue());
            }
            if (e instanceof NullLiteralExpr || e instanceof DoubleLiteralExpr || e instanceof ClassExpr) {
                return Scalar.SAFE;
            }
            if (e instanceof NameExpr n) {
                return st.get(n.getNameAsString());
            }
            if (e instanceof VariableDeclarationExpr d) {
                for (VariableDeclarator v : d.getVariables()) {
                    if (v.getType().isArrayType() || v.getType().asString().matches("(java\\.lang\\.)?String(Builder|Buffer)")) {
                        builders.add(v.getNameAsString());
                    }
                    Value value = v.getInitializer().map(i -> eval(i, st)).orElse(Scalar.SAFE);
                    st.vars.put(v.getNameAsString(), alias(v.getInitializer().orElse(null), v.getNameAsString(), value, st));
                }
                return Scalar.SAFE;
            }
            if (e instanceof AssignExpr a) {
                return assign(a, st);
            }
            if (e instanceof UnaryExpr u) {
                Scalar v = eval(u.getExpression(), st).asScalar();
                if (u.getExpression() instanceof NameExpr n && u.getOperator().name().contains("CREMENT")) {
                    st.vars.put(n.getNameAsString(), new Scalar(v.constant(), null));
                }
                if (u.getOperator() == UnaryExpr.Operator.MINUS && v.exact() instanceof Long x) {
                    return Scalar.of(-x);
                }
                if (u.getOperator() == UnaryExpr.Operator.LOGICAL_COMPLEMENT && v.exact() instanceof Boolean x) {
                    return Scalar.of(!x);
                }
                return new Scalar(v.constant(), null);
            }
            if (e instanceof BinaryExpr b) {
                return binary(b.getOperator(), eval(b.getLeft(), st).asScalar(), eval(b.getRight(), st).asScalar());
            }
            if (e instanceof ConditionalExpr c) {
                Scalar cond = eval(c.getCondition(), st).asScalar();
                if (cond.exact() instanceof Boolean taken) {
                    return eval(taken ? c.getThenExpr() : c.getElseExpr(), st);
                }
                return merge(eval(c.getThenExpr(), st), eval(c.getElseExpr(), st));
            }
            if (e instanceof ArrayCreationExpr a) {
                return a.getInitializer().map(i -> eval(i, st)).orElse(Scalar.SAFE);
            }
            if (e instanceof ArrayInitializerExpr a) {
                return new Scalar(a.getValues().stream().allMatch(v -> eval(v, st).asScalar().constant()), null);
            }
            if (e instanceof ArrayAccessExpr a) {
                eval(a.getIndex(), st);
                return new Scalar(eval(a.getName(), st).asScalar().constant(), null);
            }
            if (e instanceof ObjectCreationExpr o) {
                return create(o, st);
            }
            if (e instanceof MethodCallExpr m) {
                return call(m, st);
            }
            if (e instanceof FieldAccessExpr f && f.getNameAsString().matches("[A-Z][A-Z0-9_]*")) {
                return Scalar.SAFE; // 대문자 이름의 필드는 상수로 본다 (Java 관례에 기댄 가정)
            }
            // 필드 접근, 람다, 메서드 참조 등: 따라가지 않는다. 안에서 쓰는 바뀔 수 있는 지역 변수는 바뀌었다고 본다
            e.findAll(Expression.class).forEach(c -> sinks.replace(c, false));
            forgetMutablesIn(e, st);
            return Scalar.UNKNOWN;
        }

        /** StringBuilder·배열·List·Map 변수. 같은 객체를 여러 이름이 가리키거나 다른 코드가 바꿀 수 있다. */
        private boolean mutable(String name, State st) {
            return builders.contains(name) || st.vars.containsKey(name) && !(st.get(name) instanceof Scalar);
        }

        private void forgetMutablesIn(Node node, State st) {
            node.findAll(NameExpr.class).stream().map(NameExpr::getNameAsString)
                    .filter(n -> mutable(n, st)).toList()
                    .forEach(n -> st.vars.put(n, Scalar.UNKNOWN));
        }

        /** b = a 처럼 바뀔 수 있는 객체를 두 이름이 가리키게 되면, 한쪽으로 바꾼 것을 따라갈 수 없으니 둘 다 모른다고 본다. */
        private Value alias(Expression from, String to, Value value, State st) {
            if (from instanceof NameExpr n && (mutable(n.getNameAsString(), st) || builders.contains(to))) {
                st.vars.put(n.getNameAsString(), Scalar.UNKNOWN);
                return Scalar.UNKNOWN;
            }
            return value;
        }

        private Value assign(AssignExpr a, State st) {
            Value value = eval(a.getValue(), st);
            Expression target = a.getTarget();
            if (target instanceof NameExpr n) {
                String name = n.getNameAsString();
                if (a.getOperator() != AssignExpr.Operator.ASSIGN) {
                    value = binary(a.getOperator().toBinaryOperator().orElseThrow(), st.get(name).asScalar(), value.asScalar());
                }
                value = alias(a.getValue(), name, value, st);
                st.vars.put(name, value);
                return value;
            }
            if (target instanceof ArrayAccessExpr arr && arr.getName() instanceof NameExpr n) {
                Scalar old = st.get(n.getNameAsString()).asScalar();
                st.vars.put(n.getNameAsString(), new Scalar(old.constant() && value.asScalar().constant(), null));
            }
            return value; // 필드 대입: 필드는 어차피 상수로 보지 않는다
        }

        private Value create(ObjectCreationExpr o, State st) {
            String type = o.getType().getNameAsString();
            List<Scalar> args = o.getArguments().stream().map(a -> eval(a, st).asScalar()).toList();
            if (o.getAnonymousClassBody().isPresent()) {
                o.getAnonymousClassBody().get().forEach(b -> forgetMutablesIn(b, st));
                return Scalar.UNKNOWN;
            }
            if (spec.constructors().contains(type)) {
                // new FileInputStream(new File(name))처럼 겹쳐 쓰는 경로·프로세스 객체: 인자가 모두 상수면 상수
                return new Scalar(args.stream().allMatch(Scalar::constant), null);
            }
            boolean empty = args.isEmpty() || args.size() == 1 && args.get(0).exact() instanceof Long; // 빈 컬렉션 (크기만 지정)
            if (type.endsWith("List") && empty) {
                return new ListValue(List.of(), true);
            }
            if (type.endsWith("Map") && empty) {
                return new MapValue(Map.of(), true);
            }
            if (type.equals("String") || type.equals("StringBuilder") || type.equals("StringBuffer")) {
                boolean constant = args.stream().allMatch(Scalar::constant);
                Object exact = args.isEmpty() ? "" : args.size() == 1 && args.get(0).exact() instanceof String s ? s : null;
                return new Scalar(constant, exact);
            }
            return Scalar.UNKNOWN;
        }

        private Value call(MethodCallExpr m, State st) {
            String name = m.getNameAsString();
            List<Value> args = m.getArguments().stream().map(a -> eval(a, st)).toList();
            Optional<Expression> scope = m.getScope();
            String scopeName = scope.filter(Expression::isNameExpr).map(s -> s.asNameExpr().getNameAsString()).orElse(null);
            Value receiver = scopeName != null ? st.get(scopeName) : scope.map(s -> eval(s, st)).orElse(Scalar.UNKNOWN);

            if ((receiver instanceof ListValue || receiver instanceof MapValue) && scopeName != null) {
                // 바뀔 수 있는 객체를 넣으면 나중에 바뀐 것을 따라갈 수 없으니 모르는 값으로 넣는다
                List<Value> stored = new ArrayList<>(args);
                for (int i = 0; i < stored.size(); i++) {
                    if (m.getArgument(i) instanceof NameExpr n && mutable(n.getNameAsString(), st)) {
                        stored.set(i, Scalar.UNKNOWN);
                    }
                }
                return receiver instanceof ListValue list
                        ? listCall(scopeName, list, name, stored, st)
                        : mapCall(scopeName, (MapValue) receiver, name, stored, st);
            }
            boolean argsConstant = args.stream().allMatch(Value::allConstant);
            if (name.equals("append") && receiver instanceof Scalar r) {
                Scalar result = binary(BinaryExpr.Operator.PLUS, r, args.isEmpty() ? Scalar.SAFE : args.get(0).asScalar());
                if (scopeName != null) {
                    st.vars.put(scopeName, result);
                }
                return result;
            }
            if (name.equals("getProperty") && argsConstant
                    && scope.map(Object::toString).filter(s -> s.equals("System") || s.equals("java.lang.System")).isPresent()) {
                return Scalar.SAFE; // 시스템 속성은 서버 설정이라 요청으로 바꿀 수 없다
            }
            boolean stringStatic = scope.filter(s -> s.toString().equals("String") || s.toString().equals("java.lang.String")).isPresent();
            if (PURE.contains(name) && (stringStatic || receiver instanceof Scalar)) {
                Scalar r = stringStatic ? Scalar.SAFE : receiver.asScalar();
                if (name.equals("charAt") && r.exact() instanceof String text && args.size() == 1
                        && args.get(0).asScalar().exact() instanceof Long i && i >= 0 && i < text.length()) {
                    return Scalar.of(text.charAt(i.intValue()));
                }
                return new Scalar(r.constant() && argsConstant, null);
            }
            if (spec.constructors().contains("File") && isSink(m, spec)) {
                return new Scalar(argsConstant, null); // Paths.get(...)의 결과
            }
            Optional<MethodDeclaration> target = target(m);
            Value result = target.isPresent() ? inline(target.get(), args) : Scalar.UNKNOWN;
            // 모르는 메서드(따라간 메서드도 포함): 넘겨진 지역 List·Map·StringBuilder는 바뀌었을 수 있다
            for (Expression a : m.getArguments()) {
                if (a instanceof NameExpr n && (builders.contains(n.getNameAsString()) || !(st.get(n.getNameAsString()) instanceof Scalar))) {
                    st.vars.put(n.getNameAsString(), Scalar.UNKNOWN);
                }
            }
            if (scopeName != null && (builders.contains(scopeName) || !(receiver instanceof Scalar))) {
                st.vars.put(scopeName, Scalar.UNKNOWN);
            }
            return result;
        }

        private Value listCall(String var, ListValue list, String name, List<Value> args, State st) {
            List<Scalar> items = new ArrayList<>(list.items());
            Scalar arg0 = args.isEmpty() ? null : args.get(0).asScalar();
            switch (name) {
                case "add" -> {
                    if (args.size() == 1) {
                        items.add(arg0);
                        st.vars.put(var, new ListValue(items, list.exact()));
                    } else {
                        items.add(args.get(1).asScalar());
                        st.vars.put(var, new ListValue(items, false));
                    }
                    return Scalar.SAFE;
                }
                case "remove" -> {
                    if (list.exact() && arg0.exact() instanceof Long i && i < items.size()) {
                        Scalar removed = items.remove(i.intValue());
                        st.vars.put(var, new ListValue(items, true));
                        return removed;
                    }
                    st.vars.put(var, new ListValue(items, false));
                    return new Scalar(list.allConstant(), null);
                }
                case "get" -> {
                    if (list.exact() && arg0.exact() instanceof Long i && i < items.size()) {
                        return items.get(i.intValue());
                    }
                    return new Scalar(list.allConstant(), null);
                }
                case "size", "isEmpty", "contains", "indexOf" -> {
                    return Scalar.SAFE;
                }
                default -> {
                    st.vars.put(var, Scalar.UNKNOWN);
                    return Scalar.UNKNOWN;
                }
            }
        }

        private Value mapCall(String var, MapValue map, String name, List<Value> args, State st) {
            Map<String, Scalar> entries = new HashMap<>(map.entries());
            Object key = args.isEmpty() ? null : args.get(0).asScalar().exact();
            switch (name) {
                case "put" -> {
                    boolean exact = map.exact() && key instanceof String;
                    entries.put(key instanceof String k ? k : "\u0000" + entries.size(), args.get(1).asScalar());
                    st.vars.put(var, new MapValue(entries, exact));
                    return Scalar.SAFE;
                }
                case "get" -> {
                    if (map.exact() && key instanceof String k) {
                        return entries.getOrDefault(k, Scalar.SAFE); // 없는 키는 null
                    }
                    return new Scalar(map.allConstant(), null);
                }
                case "size", "isEmpty", "containsKey", "containsValue" -> {
                    return Scalar.SAFE;
                }
                default -> {
                    st.vars.put(var, Scalar.UNKNOWN);
                    return Scalar.UNKNOWN;
                }
            }
        }
    }

    static Scalar binary(BinaryExpr.Operator op, Scalar l, Scalar r) {
        boolean constant = l.constant() && r.constant();
        Object a = l.exact();
        Object b = r.exact();
        if (a == null || b == null) {
            return new Scalar(constant, null);
        }
        if (op == BinaryExpr.Operator.PLUS && (a instanceof String || b instanceof String)) {
            return new Scalar(constant, String.valueOf(a) + b);
        }
        if (a instanceof Long x && b instanceof Long y) {
            return switch (op) {
                case PLUS -> Scalar.of(x + y);
                case MINUS -> Scalar.of(x - y);
                case MULTIPLY -> Scalar.of(x * y);
                case DIVIDE -> y == 0 ? Scalar.SAFE : Scalar.of(x / y);
                case REMAINDER -> y == 0 ? Scalar.SAFE : Scalar.of(x % y);
                case GREATER -> Scalar.of(x > y);
                case GREATER_EQUALS -> Scalar.of(x >= y);
                case LESS -> Scalar.of(x < y);
                case LESS_EQUALS -> Scalar.of(x <= y);
                case EQUALS -> Scalar.of(x.equals(y));
                case NOT_EQUALS -> Scalar.of(!x.equals(y));
                default -> new Scalar(constant, null);
            };
        }
        if (a instanceof Boolean x && b instanceof Boolean y) {
            return switch (op) {
                case AND -> Scalar.of(x && y);
                case OR -> Scalar.of(x || y);
                case EQUALS -> Scalar.of(x.equals(y));
                case NOT_EQUALS -> Scalar.of(!x.equals(y));
                default -> new Scalar(constant, null);
            };
        }
        if (a instanceof Character x && b instanceof Character y) {
            return switch (op) {
                case EQUALS -> Scalar.of(x.equals(y));
                case NOT_EQUALS -> Scalar.of(!x.equals(y));
                default -> new Scalar(constant, null);
            };
        }
        return new Scalar(constant, null);
    }
}
