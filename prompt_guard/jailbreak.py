from prompt_guard.base import BaseGuard


class JailbreakGuard(BaseGuard):
    @property
    def guard_name(self) -> str:
        return "jailbreak"

    @property
    def rules_file(self) -> str:
        return "jailbreak.json"