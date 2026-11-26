package secureview.review;

import java.util.List;

/** Unified Diff 헝크 하나 (docs/HUNK_CODE_REVIEW_DESIGN.md 5절). 줄 번호는 PR head 파일 기준이다. */
public record Hunk(String id, String filePath, String header, int oldStartLine, int oldLineCount,
                   int newStartLine, int newLineCount, String patch, List<AddedLine> addedLines) {

    public record AddedLine(int line, String code) {
    }

    public boolean added(int line) {
        return addedLines.stream().anyMatch(a -> a.line() == line);
    }
}
