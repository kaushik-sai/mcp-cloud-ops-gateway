# Refined brief template

Fill this in from the user's request and a quick look at the project. Use the XML tags: they keep the parts apart when the brief is reused in subagent prompts. Keep each part short; a section with nothing to say is left out.

```xml
<goal>
One sentence: the outcome the user wants, in their words, and why it matters to them.
</goal>

<context>
- Project, repository path, stack, versions found
- Conventions to match (style, docs, tests, branching)
- Prior decisions and work this builds on
- Constraints of the environment (OS, shell, memory, free tier only, no cloud account)
</context>

<requirements>
1. Each one testable: "X does Y when Z".
2. ...
</requirements>

<constraints>
- Must use / must not use (tools, versions, licenses, cost)
- Security: secrets, permissions, untrusted input
- Style: match existing code and docs
</constraints>

<out_of_scope>
- Things that sound related but were not asked for (candidates for a follow-up)
</out_of_scope>

<deliverables>
- Files, artifacts, PRs, docs, with their paths
</deliverables>

<acceptance_criteria>
- The exact checks that prove it is done: commands, tests, a smoke test, observed results
- What can only be checked later (CI on push, a cloud apply), stated as such
</acceptance_criteria>

<assumptions>
- Defaults chosen where the request was silent, each one easy to overrule
</assumptions>

<open_questions>
- Only the questions whose answers change the outcome; ask them with AskUserQuestion
</open_questions>
```

## Example: raw request → brief (shortened)

Raw: "add a github actions thing so people can see my checks pass"

```xml
<goal>Public, visible CI results for the repo, so reviewers see green checks without access to the private Azure DevOps project.</goal>
<context>Repo sk-devops-svc; Azure Pipelines PR gate pipelines/pr.yml stays as is; Windows agent; checks: lint, Pester, Terraform test, Trivy, promtool.</context>
<requirements>1. Workflow runs the same checks on every PR and on main. 2. Same pinned versions as the Azure templates. 3. Drift between the two pipelines fails a test.</requirements>
<constraints>No change to the Azure pipelines; actions pinned by SHA; read-only token.</constraints>
<out_of_scope>Making the new check required; deploys.</out_of_scope>
<deliverables>.github/workflows/sk-svc-checks.yml, a parity test, README badge, DECISIONS entries.</deliverables>
<acceptance_criteria>actionlint clean; every step's script run locally passes; the first PR run green.</acceptance_criteria>
<assumptions>Windows runner for the PowerShell checks, Linux runner for image and Trivy.</assumptions>
```
