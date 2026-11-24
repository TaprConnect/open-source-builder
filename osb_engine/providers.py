"""Model-independent worker contract (S06-005).

A provider turns one planned task plus bounded repository context into a *proposed* patch.
Providers never change state, never call the kernel and never decide success: the loop applies
proposals through the kernel's mutation engine and only owner-frozen external acceptance,
replayed by the kernel, can complete a task.

  deterministic  local AST repairers (osb_engine.repairs); no network, no model
  mock           returns canned proposals; proves interface compatibility only
  anthropic      Messages API     } live backends: blocked unless the owner sets
  openai         Chat Completions } OSB_LIVE_PROVIDERS_APPROVED=1 and a key is configured
"""
import hashlib
import json
import os
import urllib.request

from . import repairs


class Blocked(Exception):
    """The provider cannot run here (not authorised, not configured or unavailable)."""


class Provider:
    name = "abstract"
    kind = "abstract"
    certifies = False  # no provider output is ever completion authority

    def propose(self, task, context):
        """Return a list of {"patch": str, "strategy": str, "rationale": str} in preference order."""
        raise NotImplementedError

    def describe(self):
        return {"name": self.name, "kind": self.kind, "certifies": self.certifies}


class DeterministicProvider(Provider):
    name, kind = "deterministic", "deterministic"

    def __init__(self, root):
        self.root = root

    def propose(self, task, context):
        out = []
        for strategy in task.get("strategies") or list(repairs.REPAIRERS):
            patch = repairs.propose(self.root, task, strategy)
            if patch:
                out.append({"patch": patch, "strategy": strategy,
                            "rationale": f"deterministic {strategy} over {', '.join(task['scope'])}"})
        return out


class MockProvider(Provider):
    """Interface test double. Its results are never evidence of live model capability."""
    name, kind = "mock", "mock"

    def __init__(self, proposals):
        self.proposals = list(proposals)
        self.calls = []

    def propose(self, task, context):
        self.calls.append({"task": task["id"], "context_sha256": hashlib.sha256(context.encode()).hexdigest()})
        return [dict(p) for p in self.proposals]


_SYSTEM = ("You repair one task in a repository. Reply with JSON only: "
           '{"patch": "<unified diff touching only the allowed paths>", "rationale": "<one sentence>"}. '
           "Never modify tests, acceptance files, CI or security controls. You cannot mark work complete.")


class LiveProvider(Provider):
    kind = "live"
    endpoint = ""

    def __init__(self, model=None, api_key_env=None, endpoint=None, timeout=120, opener=None):
        self.model = model or os.environ.get(f"OSB_{self.name.upper()}_MODEL")
        self.api_key_env = api_key_env or f"OSB_{self.name.upper()}_API_KEY"
        self.endpoint = endpoint or self.endpoint
        self.timeout = timeout
        self.opener = opener or urllib.request.urlopen
        self.cache = {}

    def check(self):
        if os.environ.get("OSB_LIVE_PROVIDERS_APPROVED") != "1":
            raise Blocked(f"{self.name}: live model calls are not approved by the owner (OSB_LIVE_PROVIDERS_APPROVED)")
        if not self.model:
            raise Blocked(f"{self.name}: no model configured (OSB_{self.name.upper()}_MODEL)")
        if not os.environ.get(self.api_key_env):
            raise Blocked(f"{self.name}: no API key in {self.api_key_env}")

    def request(self, task, context):
        raise NotImplementedError

    def parse(self, body):
        raise NotImplementedError

    def propose(self, task, context):
        self.check()
        prompt = json.dumps({"task": {k: task[k] for k in ("id", "outcome", "scope", "acceptance_summary") if k in task},
                             "context": context}, sort_keys=True)
        key = hashlib.sha256((self.name + self.model + prompt).encode()).hexdigest()
        if key not in self.cache:
            req = self.request(task, prompt)
            with self.opener(req, timeout=self.timeout) as response:
                text = self.parse(json.loads(response.read()))
            try:
                value = json.loads(text)
            except ValueError:
                return []
            if not isinstance(value, dict) or not isinstance(value.get("patch"), str):
                return []
            self.cache[key] = [{"patch": value["patch"], "strategy": f"{self.name}:{self.model}",
                                "rationale": str(value.get("rationale", ""))[:500]}]
        return self.cache[key]


class AnthropicProvider(LiveProvider):
    name, endpoint = "anthropic", "https://api.anthropic.com/v1/messages"

    def request(self, task, prompt):
        body = {"model": self.model, "max_tokens": 4096, "system": _SYSTEM,
                "messages": [{"role": "user", "content": prompt}]}
        return urllib.request.Request(self.endpoint, json.dumps(body).encode(), method="POST", headers={
            "content-type": "application/json", "anthropic-version": "2023-06-01",
            "x-api-key": os.environ[self.api_key_env]})

    def parse(self, body):
        return "".join(part.get("text", "") for part in body.get("content", []) if part.get("type") == "text")


class OpenAIProvider(LiveProvider):
    name, endpoint = "openai", "https://api.openai.com/v1/chat/completions"

    def request(self, task, prompt):
        body = {"model": self.model, "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": _SYSTEM}, {"role": "user", "content": prompt}]}
        return urllib.request.Request(self.endpoint, json.dumps(body).encode(), method="POST", headers={
            "content-type": "application/json", "authorization": "Bearer " + os.environ[self.api_key_env]})

    def parse(self, body):
        choices = body.get("choices") or [{}]
        return (choices[0].get("message") or {}).get("content") or ""


def context(root, task, max_bytes=48_000):
    """Bounded context: the task's scope files, truncated deterministically."""
    parts, used = [], 0
    for path in task["scope"]:
        try:
            data = (root / path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        chunk = f"### {path}\n{data}"[: max(0, max_bytes - used)]
        parts.append(chunk)
        used += len(chunk)
        if used >= max_bytes:
            break
    return "\n".join(parts)


def build(name, root, **kwargs):
    if name == "deterministic":
        return DeterministicProvider(root)
    if name == "anthropic":
        return AnthropicProvider(**kwargs)
    if name == "openai":
        return OpenAIProvider(**kwargs)
    raise ValueError(f"unknown provider {name}")
