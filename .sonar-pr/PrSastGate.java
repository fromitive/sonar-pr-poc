import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * PR 보안 게이트 (MVP)
 *
 * 1) SonarQube 분석(CE task) 완료 확인
 * 2) git diff merge-base..HEAD 로 PR 변경 라인 계산
 * 3) 변경 라인 이슈는 차단 후보, 변경 파일의 Diff 외부 Security 이슈는 경고
 * 4) GitHub annotation + Step Summary + sast-result.md 출력
 *
 * 종료 코드: 0 = 통과, 1 = 차단 이슈 존재, 2 = 스캔/조회 실패 (fail-closed)
 *
 * 실행: java -cp "<jackson jar 디렉터리>/*" PrSastGate.java
 */
public class PrSastGate {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();
    private static final Pattern HUNK = Pattern.compile("^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,(\\d+))? @@");
    private static final Path RESULT_FILE = Path.of("sast-result.md");
    private static final int PAGE_SIZE = 500;

    private static String host;
    private static String token;
    private static String projectKey;
    private static final Map<String, RuleInfo> RULES = new HashMap<>();

    record Finding(String kind, String key, String rule, String path,
                   int startLine, int endLine, String message, String severity) {}

    record RuleInfo(String name, String howToFix) {}

    public static void main(String[] args) {
        int code;
        try {
            code = run();
        } catch (Exception e) {
            System.out.println("::error title=SAST 스캔 실패::" + escapeData(e.toString()));
            writeReport("## ❌ SAST 스캔 실패\n\n"
                    + "보안 검사가 완료되지 않았습니다. **이 상태로는 병합할 수 없습니다.** "
                    + "Actions 로그를 확인한 뒤 다시 실행하세요.\n\n```\n" + e + "\n```\n");
            code = 2;
        }
        System.exit(code);
    }

    static int run() throws Exception {
        host = stripTrailingSlash(env("SONAR_HOST_URL", null));
        token = env("SONAR_TOKEN", null);
        projectKey = env("SONAR_PROJECT_KEY", null);
        String mergeBase = env("MERGE_BASE", null);
        Set<String> blockSeverities = parseSet(env("BLOCK_SEVERITIES", "BLOCKER,HIGH"));
        Path reportTask = Path.of(env("REPORT_TASK_FILE", "build/sonar/report-task.txt"));
        Duration ceTimeout = Duration.ofMinutes(Long.parseLong(env("CE_TIMEOUT_MINUTES", "10")));

        // 1) 이번 분석이 서버에서 정상 처리됐는지 확인 (실패/타임아웃 → 예외 → 종료 코드 2)
        if (!Files.exists(reportTask)) {
            throw new IllegalStateException(reportTask + " 가 없습니다. SonarQube 분석이 실행되지 않았습니다.");
        }
        String ceTaskId = readProperties(reportTask).getProperty("ceTaskId");
        if (ceTaskId == null || ceTaskId.isBlank()) {
            throw new IllegalStateException(reportTask + " 에 ceTaskId가 없습니다.");
        }
        waitForCeTask(ceTaskId, ceTimeout);

        // 2) PR 변경 라인 (merge-base..HEAD, 새 파일 기준 라인 번호)
        Map<String, BitSet> changed = changedLines(mergeBase);
        System.out.printf("변경 파일 %d개 (merge-base %s)%n", changed.size(), mergeBase);

        // 3) 전체 분석 이슈 → 변경 라인 / 변경 파일의 나머지 라인으로 분리
        // 삭제만 있는 변경도 "변경 파일" 경고 범위에 포함한다.
        Set<String> changedFiles = changedFiles(mergeBase);
        List<Finding> allIssues = fetchSecurityIssues();
        List<Finding> diffIssues = inDiff(allIssues, changed);
        Set<String> diffKeys = diffIssues.stream().map(Finding::key).collect(Collectors.toSet());
        List<Finding> fileWarnings = allIssues.stream()
                .filter(f -> changedFiles.contains(f.path()) && !diffKeys.contains(f.key()))
                .toList();
        List<Finding> hotspots = inDiff(fetchHotspots(), changed);
        List<Finding> blocking = diffIssues.stream()
                .filter(f -> blockSeverities.contains(f.severity())).toList();
        List<Finding> lineWarnings = diffIssues.stream()
                .filter(f -> !blockSeverities.contains(f.severity())).toList();

        // 4) 출력: 차단은 변경 라인만, 변경 파일의 나머지는 경고만
        annotate(blocking, "error");
        annotate(lineWarnings, "warning");
        // Diff 외부 라인은 GitHub PR annotation이 표시되지 않을 수 있어 요약 리포트에만 기록
        annotate(hotspots, "notice");
        writeReport(buildReport(blocking, lineWarnings, fileWarnings, hotspots, blockSeverities, mergeBase));

        System.out.printf("차단 %d / 변경 라인 경고 %d / 변경 파일 경고 %d / Hotspot %d%n",
                blocking.size(), lineWarnings.size(), fileWarnings.size(), hotspots.size());
        return blocking.isEmpty() ? 0 : 1;
    }

    // ---------------------------------------------------------------- SonarQube

    static void waitForCeTask(String taskId, Duration timeout) throws Exception {
        Instant deadline = Instant.now().plus(timeout);
        while (true) {
            JsonNode task = get("/api/ce/task?id=" + enc(taskId)).path("task");
            String status = task.path("status").asText();
            if ("SUCCESS".equals(status)) {
                String component = task.path("componentKey").asText();
                if (!projectKey.equals(component)) {
                    throw new IllegalStateException("분석 대상 프로젝트 불일치: 기대=" + projectKey + ", 실제=" + component);
                }
                System.out.println("분석 완료: analysisId=" + task.path("analysisId").asText());
                return;
            }
            if ("FAILED".equals(status) || "CANCELED".equals(status)) {
                throw new IllegalStateException("SonarQube 분석 " + status + ": " + task.path("errorMessage").asText(""));
            }
            if (Instant.now().isAfter(deadline)) {
                throw new IllegalStateException("분석 대기 시간 초과(" + timeout.toMinutes() + "분), 마지막 상태=" + status);
            }
            Thread.sleep(3000);
        }
    }

    static List<Finding> fetchSecurityIssues() throws Exception {
        List<Finding> list = new ArrayList<>();
        for (int page = 1; ; page++) {
            JsonNode res = get("/api/issues/search?components=" + enc(projectKey)
                    + "&impactSoftwareQualities=SECURITY&issueStatuses=OPEN,CONFIRMED"
                    + "&ps=" + PAGE_SIZE + "&p=" + page);
            for (JsonNode i : res.path("issues")) {
                String severity = "UNKNOWN";
                for (JsonNode impact : i.path("impacts")) {
                    if ("SECURITY".equals(impact.path("softwareQuality").asText())) {
                        severity = impact.path("severity").asText();
                    }
                }
                int[] lines = lines(i);
                list.add(new Finding("ISSUE", i.path("key").asText(), i.path("rule").asText(),
                        toPath(i.path("component").asText()), lines[0], lines[1],
                        i.path("message").asText(), severity));
            }
            if (page * PAGE_SIZE >= res.path("paging").path("total").asInt() || page >= 20) {
                return list;
            }
        }
    }

    static List<Finding> fetchHotspots() throws Exception {
        List<Finding> list = new ArrayList<>();
        for (int page = 1; ; page++) {
            JsonNode res = get("/api/hotspots/search?project=" + enc(projectKey)
                    + "&status=TO_REVIEW&ps=" + PAGE_SIZE + "&p=" + page);
            for (JsonNode h : res.path("hotspots")) {
                int[] lines = lines(h);
                list.add(new Finding("HOTSPOT", h.path("key").asText(), h.path("ruleKey").asText(),
                        toPath(h.path("component").asText()), lines[0], lines[1],
                        h.path("message").asText(), h.path("vulnerabilityProbability").asText("UNKNOWN")));
            }
            if (page * PAGE_SIZE >= res.path("paging").path("total").asInt() || page >= 20) {
                return list;
            }
        }
    }

    static RuleInfo rule(String ruleKey) {
        return RULES.computeIfAbsent(ruleKey, k -> {
            try {
                JsonNode r = get("/api/rules/show?key=" + enc(k)).path("rule");
                String howToFix = "";
                for (JsonNode s : r.path("descriptionSections")) {
                    if ("how_to_fix".equals(s.path("key").asText())) {
                        howToFix = plain(s.path("content").asText());
                        break;
                    }
                }
                return new RuleInfo(r.path("name").asText(k), howToFix);
            } catch (Exception e) {
                return new RuleInfo(k, "");
            }
        });
    }

    static JsonNode get(String pathAndQuery) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(host + pathAndQuery))
                .header("Authorization", "Bearer " + token)
                .timeout(Duration.ofSeconds(30))
                .GET().build();
        HttpResponse<String> res = HTTP.send(req, HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) {
            throw new IllegalStateException("GET " + pathAndQuery + " → HTTP " + res.statusCode()
                    + " " + truncate(res.body(), 300));
        }
        return JSON.readTree(res.body());
    }

    // ---------------------------------------------------------------- Git diff

    /** merge-base..HEAD 사이에 추가·수정된 라인(새 파일 기준 번호)을 파일별로 반환 */
    static Map<String, BitSet> changedLines(String mergeBase) throws Exception {
        Process p = new ProcessBuilder("git", "-c", "core.quotePath=false", "diff", "--no-color", "--no-ext-diff",
                "--unified=0", "-M", "--src-prefix=a/", "--dst-prefix=b/", mergeBase, "HEAD")
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (p.waitFor() != 0) {
            throw new IllegalStateException("git diff 실패 (merge-base=" + mergeBase + ")");
        }
        Map<String, BitSet> result = new HashMap<>();
        String file = null;
        String prev = "";
        for (String line : out.split("\n")) {
            if (line.startsWith("+++ ") && prev.startsWith("--- ")) {
                String path = line.substring(4).replaceAll("\t$", "");
                file = path.startsWith("b/") ? path.substring(2) : null; // /dev/null = 삭제된 파일
            } else if (file != null && line.startsWith("@@")) {
                Matcher m = HUNK.matcher(line);
                if (m.find()) {
                    int start = Integer.parseInt(m.group(1));
                    int count = m.group(2) == null ? 1 : Integer.parseInt(m.group(2));
                    if (count > 0) { // count==0 은 삭제만 있는 hunk
                        result.computeIfAbsent(file, k -> new BitSet()).set(start, start + count);
                    }
                }
            }
            prev = line;
        }
        return result;
    }

    /** PR에서 변경된 파일 이름 전체 (삭제된 파일 제외). 삭제만 한 수정도 포함. */
    static Set<String> changedFiles(String mergeBase) throws Exception {
        Process p = new ProcessBuilder("git", "-c", "core.quotePath=false", "diff", "--name-only",
                "-z", "--diff-filter=ACMRT", "-M", mergeBase, "HEAD")
                .redirectError(ProcessBuilder.Redirect.INHERIT)
                .start();
        byte[] output = p.getInputStream().readAllBytes();
        if (p.waitFor() != 0) {
            throw new IllegalStateException("git diff --name-only 실패 (merge-base=" + mergeBase + ")");
        }
        Set<String> files = new HashSet<>();
        String raw = new String(output, StandardCharsets.UTF_8);
        for (String file : raw.split("\\x00")) {
            if (!file.isEmpty()) files.add(file);
        }
        return files;
    }

    static List<Finding> inDiff(List<Finding> all, Map<String, BitSet> changed) {
        return all.stream().filter(f -> {
            BitSet bits = changed.get(f.path());
            if (bits == null) {
                return false;
            }
            if (f.startLine() <= 0) {
                return true; // 라인 정보 없는 파일 단위 이슈: 파일이 바뀌었으면 대상
            }
            int next = bits.nextSetBit(f.startLine());
            return next != -1 && next <= f.endLine();
        }).toList();
    }

    // ---------------------------------------------------------------- 출력

    static void annotate(List<Finding> findings, String level) {
        for (Finding f : findings) {
            StringBuilder sb = new StringBuilder("::").append(level)
                    .append(" file=").append(escapeProp(f.path()));
            if (f.startLine() > 0) {
                sb.append(",line=").append(f.startLine()).append(",endLine=").append(f.endLine());
            }
            sb.append(",title=").append(escapeProp("[" + f.severity() + "] " + f.rule()))
              .append("::").append(escapeData(f.message()));
            System.out.println(sb);
        }
    }

    static String buildReport(List<Finding> blocking, List<Finding> lineWarnings,
                              List<Finding> fileWarnings, List<Finding> hotspots,
                              Set<String> blockSeverities, String mergeBase) {
        StringBuilder sb = new StringBuilder();
        sb.append(blocking.isEmpty()
                ? "## ✅ SAST 통과 — PR 변경 코드에 차단 대상 보안 이슈가 없습니다\n\n"
                : "## ❌ SAST 차단 — PR 변경 코드에 보안 이슈 " + blocking.size() + "건\n\n");
        sb.append("| 구분 | 건수 |\n|---|---|\n")
          .append("| 차단 (").append(String.join("/", new TreeSet<>(blockSeverities))).append(") | ")
          .append(blocking.size()).append(" |\n")
          .append("| 변경 라인 경고 (그 외 심각도) | ").append(lineWarnings.size()).append(" |\n")
          .append("| 변경 파일 경고 (Diff 외부, 심각도 무관) | ").append(fileWarnings.size()).append(" |\n")
          .append("| 변경 라인 Hotspot (검토 권장, 차단 안 함) | ").append(hotspots.size()).append(" |\n\n")
          .append("분석 범위: SonarQube 프로젝트 전체. 차단 범위: `")
          .append(shortSha(mergeBase)).append("..HEAD` 추가·수정 라인. 변경 파일의 나머지 이슈는 경고만. 프로젝트 `")
          .append(projectKey).append("`\n\n");

        section(sb, "차단 이슈 (수정해야 병합 가능)", blocking, true);
        section(sb, "변경 라인 경고 (차단 대상 외 심각도)", lineWarnings, true);
        section(sb, "변경 파일의 다른 라인에 있는 보안 이슈 (차단하지 않음)", fileWarnings, true);
        section(sb, "Security Hotspot (변경 라인)", hotspots, false);

        if (!blocking.isEmpty()) {
            sb.append("### 오탐이라고 판단되면\n")
              .append("AppSec 담당자에게 요청하세요. SonarQube에서 해당 이슈를 *False Positive* 또는 *Accept* 로 처리한 뒤 ")
              .append("이 워크플로를 **Re-run** 하면 집계에서 빠집니다.\n");
        }
        return sb.toString();
    }

    static void section(StringBuilder sb, String title, List<Finding> list, boolean withGuide) {
        if (list.isEmpty()) {
            return;
        }
        sb.append("### ").append(title).append("\n\n")
          .append("| 심각도 | 룰 | 위치 | 내용 |\n|---|---|---|---|\n");
        for (Finding f : list) {
            String link = "HOTSPOT".equals(f.kind())
                    ? host + "/security_hotspots?id=" + enc(projectKey) + "&hotspots=" + enc(f.key())
                    : host + "/project/issues?id=" + enc(projectKey) + "&open=" + enc(f.key());
            sb.append("| ").append(f.severity())
              .append(" | `").append(f.rule()).append("` ").append(cell(rule(f.rule()).name()))
              .append(" | [").append(cell(f.path())).append(":").append(f.startLine()).append("](").append(link).append(")")
              .append(" | ").append(cell(f.message())).append(" |\n");
        }
        sb.append("\n");
        if (withGuide) {
            Set<String> seen = new LinkedHashSet<>();
            list.forEach(f -> seen.add(f.rule()));
            for (String r : seen) {
                RuleInfo info = rule(r);
                sb.append("<details><summary>수정 가이드: <code>").append(r).append("</code> ")
                  .append(info.name()).append("</summary>\n\n")
                  .append(info.howToFix().isEmpty() ? "(가이드 없음)" : truncate(info.howToFix(), 800))
                  .append("\n\n[룰 상세](").append(host).append("/coding_rules?open=").append(enc(r))
                  .append("&rule_key=").append(enc(r)).append(")\n\n</details>\n\n");
            }
        }
    }

    static void writeReport(String markdown) {
        try {
            Files.writeString(RESULT_FILE, markdown, StandardCharsets.UTF_8);
            String summary = System.getenv("GITHUB_STEP_SUMMARY");
            if (summary != null && !summary.isBlank()) {
                Files.writeString(Path.of(summary), markdown + "\n", StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            }
        } catch (Exception e) {
            System.out.println("::warning::리포트 파일 작성 실패: " + escapeData(e.toString()));
        }
    }

    // ---------------------------------------------------------------- 유틸

    static int[] lines(JsonNode n) {
        JsonNode tr = n.path("textRange");
        if (tr.has("startLine")) {
            return new int[]{tr.path("startLine").asInt(), tr.path("endLine").asInt(tr.path("startLine").asInt())};
        }
        if (n.has("line")) {
            return new int[]{n.path("line").asInt(), n.path("line").asInt()};
        }
        return new int[]{0, 0};
    }

    /** "projectKey:src/main/java/..." → "src/main/java/..." */
    static String toPath(String component) {
        String prefix = projectKey + ":";
        return component.startsWith(prefix) ? component.substring(prefix.length()) : component;
    }

    static Properties readProperties(Path path) throws Exception {
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(path)) {
            props.load(in);
        }
        return props;
    }

    static String env(String name, String defaultValue) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) {
            if (defaultValue == null) {
                throw new IllegalStateException("환경변수 누락: " + name);
            }
            return defaultValue;
        }
        return v.trim();
    }

    static Set<String> parseSet(String csv) {
        return Arrays.stream(csv.split(",")).map(String::trim).map(s -> s.toUpperCase(Locale.ROOT))
                .filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    static String plain(String html) {
        return html.replaceAll("(?s)<pre>.*?</pre>", " [코드 예시는 룰 상세 참고] ")
                .replaceAll("<[^>]+>", " ")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&amp;", "&")
                .replaceAll("\\s+", " ").trim();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    static String cell(String s) {
        return s.replace("|", "\\|").replace("\n", " ");
    }

    static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    static String shortSha(String sha) {
        return sha.length() > 10 ? sha.substring(0, 10) : sha;
    }

    static String stripTrailingSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    /** GitHub workflow command 메시지 이스케이프 */
    static String escapeData(String s) {
        return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A");
    }

    /** GitHub workflow command 속성 이스케이프 */
    static String escapeProp(String s) {
        return escapeData(s).replace(":", "%3A").replace(",", "%2C");
    }
}
