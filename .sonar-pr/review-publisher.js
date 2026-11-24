const fs = require('fs');

// GitHub Actions의 github-script에서 호출
module.exports = async ({ github, context, core }) => {
    const filename = 'sast-findings.json';

    if (!fs.existsSync(filename)) {
        core.warning('SAST findings JSON 없음: 인라인 리뷰를 건너뜁니다.');
        return;
    }

    const data = JSON.parse(fs.readFileSync(filename, 'utf8'));

    const { owner, repo } = context.repo;
    const pull_number = context.payload.pull_request.number;
    const sha = context.payload.pull_request.head.sha;

    // 이전 커밋의 검사 결과를 재사용하지 않도록 확인
    if (data.headSha !== sha) {
        throw new Error(
        `이전 결과 재사용 방지: ${data.headSha} != ${sha}`
        );
    }

    // 기존 PR 리뷰 댓글 조회
    const existing = await github.paginate(
        github.rest.pulls.listReviewComments,
        {
        owner,
        repo,
        pull_number,
        per_page: 100
        }
    );

    // SonarQube Issue Key 또는 룰·경로·라인 기준 중복 확인
    const isDuplicate = (f) => existing.some(c =>
        c.body?.includes(`<!-- sonar-sast-issue:${f.key} -->`) ||
        (
        c.body?.includes(`<!-- sonar-sast-rule:${f.rule} -->`) &&
        c.path === f.path &&
        (
            c.line === f.startLine ||
            c.original_line === f.startLine
        )
        )
    );

    // PR에서 변경된 파일 조회
    const changed = await github.paginate(
        github.rest.pulls.listFiles,
        {
        owner,
        repo,
        pull_number,
        per_page: 100
        }
    );

    const patchFiles = new Set(
        changed
        .filter(f =>
            f.status !== 'removed' &&
            typeof f.patch === 'string'
        )
        .map(f => f.filename)
    );

    let posted = 0;
    let skipped = 0;

    const reviewLinks = [];
    const failures = [];

    // 변경 라인의 차단 이슈 및 경고 이슈
    const findings = [
        ...(data.blocking || []),
        ...(data.lineWarnings || [])
    ];

    for (const f of findings) {

        if (
        !f.path ||
        !Number.isInteger(f.startLine) ||
        f.startLine <= 0 ||
        !patchFiles.has(f.path)
        ) {
        skipped++;
        continue;
        }

        // 기존 댓글이 있으면 다시 만들지 않음
        if (isDuplicate(f)) {
        const prior = existing.find(c =>
            c.body?.includes(
            `<!-- sonar-sast-issue:${f.key} -->`
            ) ||
            (
            c.body?.includes(
                `<!-- sonar-sast-rule:${f.rule} -->`
            ) &&
            c.path === f.path &&
            (
                c.line === f.startLine ||
                c.original_line === f.startLine
            )
            )
        );

        if (prior?.html_url) {
            reviewLinks.push({
            ...f,
            url: prior.html_url
            });
        }

        skipped++;
        continue;
        }

        // 리뷰 댓글 본문 생성
        const body = [
        `🔒 **[${f.severity}] ${f.rule}**`,
        '',
        f.message || 'SonarQube 보안 규칙 위반',
        '',
        `SonarQube Issue: \`${f.key}\``,
        '',
        '수정 또는 오탐 검토가 필요합니다.',
        '차단 여부는 SAST Gate 결과를 따릅니다.',
        '',
        `<!-- sonar-sast-issue:${f.key} -->`,
        `<!-- sonar-sast-rule:${f.rule} -->`
        ].join('\n');

        try {

        // 실제 GitHub PR 인라인 리뷰 댓글 생성
        const response =
            await github.rest.pulls.createReviewComment({
            owner,
            repo,
            pull_number,
            commit_id: sha,
            path: f.path,
            line: f.startLine,
            side: 'RIGHT',
            body
            });

        existing.push(response.data);

        reviewLinks.push({
            ...f,
            url: response.data.html_url
        });

        posted++;

        } catch (e) {

        failures.push(
            `${f.path}:${f.startLine} ${f.rule}: ` +
            `HTTP ${e.status || 'unknown'}`
        );
        }
    }

    // 요약 댓글의 코드 링크를 실제 Review Comment 링크로 교체
    if (fs.existsSync('sast-result.md')) {

        const lines = fs.readFileSync(
        'sast-result.md',
        'utf8'
        ).split('\n');

        for (const item of reviewLinks) {

        const label =
            `[${item.path}:${item.startLine}]`;

        for (let n = 0; n < lines.length; n++) {

            if (
            !lines[n].startsWith('|') ||
            !lines[n].includes('`' + item.rule + '`') ||
            !lines[n].includes(label + '(')
            ) {
            continue;
            }

            const at =
            lines[n].indexOf(label + '(') +
            label.length + 1;

            const end = lines[n].indexOf(')', at);

            if (end > at) {
            lines[n] =
                lines[n].slice(0, at) +
                item.url +
                lines[n].slice(end);
            }
        }
        }

        fs.writeFileSync(
        'sast-result.md',
        lines.join('\n'),
        'utf8'
        );
    }

    core.info(
        `SAST Review: 새 댓글 ${posted}, ` +
        `생략 ${skipped}, 실패 ${failures.length}`
    );

    for (const msg of failures) {
        core.warning(
        `인라인 리뷰 실패: ${msg} (PR 요약 댓글에서 확인)`
        );
    }
};
