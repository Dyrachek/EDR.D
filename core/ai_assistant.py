import os
import sys
from pathlib import Path

def get_base_dir() -> Path:
    """Папка рядом с exe (или корень проекта при запуске из Python)"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent

MODELS_DIR = get_base_dir() / "models"

MODEL_CANDIDATES = [
    "qwen2.5-1.5b-instruct-q4_k_m.gguf",
    "qwen2.5-1.5b-instruct-q4_0.gguf",
    "model.gguf",
]


class AIAssistant:
    def __init__(self):
        self.llm = None
        self.available = False
        self.model_path = self._find_model()
        self._load_model()

    def _find_model(self):
        if not MODELS_DIR.exists():
            return None
        for name in MODEL_CANDIDATES:
            path = MODELS_DIR / name
            if path.exists():
                return str(path)
        ggufs = list(MODELS_DIR.glob("*.gguf"))
        if ggufs:
            return str(ggufs[0])
        return None

    def _load_model(self):
        log_path = get_base_dir() / "ai_debug.log"
        try:
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"BASE: {get_base_dir()}\n")
                f.write(f"MODELS_DIR: {MODELS_DIR}\n")
                f.write(f"exists: {MODELS_DIR.exists()}\n")
                f.write(f"model_path: {self.model_path}\n")
        except Exception:
            pass

        if not self.model_path:
            self.available = False
            return
        try:
            from llama_cpp import Llama
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=2048,
                n_threads=max(2, (os.cpu_count() or 4) // 2),
                verbose=False,
            )
            self.available = True
            with open(log_path, "a", encoding="utf-8") as f:
                f.write("LOAD: OK\n")
        except Exception as e:
            self.llm = None
            self.available = False
            try:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"LOAD ERROR: {e}\n")
            except Exception:
                pass

    def ask(self, prompt: str, system: str = None) -> str:
        if not self.available or self.llm is None:
            return (
                "Локальная модель не загружена.\n"
                f"Ожидался файл в: {MODELS_DIR}\n"
                "Положи .gguf в папку models рядом с EDR.D.exe"
            )

        system = system or (
            "Ты — ассистент SOC-аналитика. Отвечай кратко на русском, по делу."
        )

        full_prompt = (
            f"<|im_start|>system\n{system}<|im_end|>\n"
            f"<|im_start|>user\n{prompt}<|im_end|>\n"
            f"<|im_start|>assistant\n"
        )

        try:
            out = self.llm(
                full_prompt,
                max_tokens=350,
                temperature=0.3,
                stop=["<|im_end|>", "<|im_start|>"],
            )
            text = out["choices"][0]["text"].strip()
            return text if text else "Пустой ответ модели"
        except Exception as e:
            return f"Ошибка AI: {e}"

    def explain_alert(self, alert_message: str) -> str:
        system = (
            "Ты — ассистент SOC-аналитика. Отвечай кратко на русском. "
            "Оцени риск и что проверить."
        )
        prompt = (
            f"Объясни алерт из EDR:\n\n{alert_message}\n\n"
            f"Кратко:\n1) Что это значит\n2) Риск (низкий/средний/высокий)\n3) Что делать"
        )
        return self.ask(prompt, system)

    def analyze_process(self, name: str, path: str, cpu: float, memory: float, reason: str = "") -> str:
        system = "Ты — ассистент SOC-аналитика. Отвечай кратко на русском."
        prompt = (
            f"Проанализируй процесс:\n"
            f"Имя: {name}\n"
            f"Путь: {path}\n"
            f"CPU: {cpu}%\n"
            f"Память: {memory}%\n"
            f"Причина детекции: {reason or 'нет'}\n\n"
            f"Кратко: подозрительный или нет, почему, что проверить."
        )
        return self.ask(prompt, system)

    def summarize_session(self, alerts: list, process_count: int, connection_count: int) -> str:
        system = "Ты — ассистент SOC-аналитика. Отвечай кратко на русском."
        alerts_text = "\n".join(
            f"- {a.get('time', '')}: {a.get('message', '')}" for a in alerts[:10]
        ) or "Алертов нет"

        prompt = (
            f"Сводка сессии мониторинга:\n"
            f"Процессов: {process_count}\n"
            f"Соединений: {connection_count}\n"
            f"Алерты:\n{alerts_text}\n\n"
            f"2–4 предложения: общая картина и на что смотреть."
        )
        return self.ask(prompt, system)