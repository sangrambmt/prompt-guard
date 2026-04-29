from prompt_guard.base import BaseGuard


class InjectionGuard(BaseGuard):
    @property
    def guard_name(self) -> str:
        return "injection"

    @property
    def rules_file(self) -> str:
        return "injection.json"