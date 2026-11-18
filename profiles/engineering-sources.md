# Public engineering guidance

These are public references for designing review criteria. Organisations can have additional private controls. Use a dated source and record the exact revision of each local evaluation dataset, grader and configuration. Model-development frameworks require tailoring to the risk and capability of the product.

| Source | Practice adapted here | Controls |
| --- | --- | --- |
| [OpenAI evaluation best practices](https://developers.openai.com/api/docs/guides/evaluation-best-practices) | Define the goal, use representative examples, set criteria, compare changes and keep evaluating. | AIEvals, Grounding |
| [OpenAI deployment safety hub](https://deploymentsafety.openai.com/) | Document measured capabilities, mitigations and limitations for a release. | AIRelease |
| [Anthropic agent evaluations](https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents) | Evaluate end states, use repeated trials and calibrate graders against human judgement. | AITrials, AIOutcome |
| [Anthropic building effective agents](https://www.anthropic.com/engineering/building-effective-agents) | Choose bounded workflows where sufficient; design clearly scoped tools. | AIResources, Agent |
| [Google DeepMind Frontier Safety Framework](https://deepmind.google/blog/introducing-the-frontier-safety-framework/) | Adapt the concept of capability thresholds and mitigation review to the actual release risk. | AIRelease |
| [Google SRE canarying releases](https://sre.google/workbook/canarying-releases/) | Compare release candidates with a baseline and define stop and recovery conditions. | Canary, Reliability |
| [OWASP ASVS](https://asvs.owasp.org/) | Select applicable defensive verification requirements by system boundary. | WebDefences, Identity, Isolation |
| [WCAG 2.2](https://www.w3.org/TR/WCAG22/) | Bind accessibility findings to criteria and user tasks. | Accessibility, UX |
